// core/BeforeSnapshot.js
//
// User Story A3 (5 pts · High)
// As a developer, I want to capture a "before" snapshot of my system
// state prior to installing a package, so that I have a clean baseline
// to compare against.
//
// This module owns the *generic* snapshot engine: it defines the
// snapshot shape, orchestrates a set of pluggable "collectors", and
// produces the baseline object. Deeper, security-specific collectors
// (SSH keys, sudoers, startup items -> A8; systemd/registry -> G1/G2)
// register themselves into this same engine later; A3 ships with the
// general-purpose collectors it needs to be useful on its own:
// env vars, PATH entries, running processes, open network ports,
// and the OS temp directory listing.

'use strict';

const os = require('os');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFile } = require('child_process');
const { detectOs } = require('./OsDetection');
const { detectPackageManagers } = require('./PackageManagerDetection');

/** Runs a command and resolves to trimmed stdout, or '' on any failure. Never rejects. */
function run(command, args) {
  return new Promise((resolve) => {
    execFile(command, args, { timeout: 8000, windowsHide: true, maxBuffer: 10 * 1024 * 1024 }, (error, stdout) => {
      resolve(error ? '' : String(stdout));
    });
  });
}

/** Collects a copy of the current environment variables. */
function collectEnvVars() {
  return { ...process.env };
}

/** Collects PATH entries, in order, exactly as the shell would see them. */
function collectPath() {
  const raw = process.env.PATH || process.env.Path || '';
  const separator = os.platform() === 'win32' ? ';' : ':';
  return raw.split(separator).filter(Boolean);
}

/**
 * Collects the contents of shell/profile configuration files relevant
 * to the current OS, so tampering (e.g. an injected malicious alias
 * or PATH prepend) can be detected even if it doesn't show up as a
 * running-process or env-var change at capture time. Missing files
 * are simply omitted.
 *
 * The actual list of files checked is OS-specific and comes from the
 * config file (D1's Config.js: config.shellConfigFiles.<osId>) so it
 * can be edited without touching code — e.g. adding a shell you use
 * that isn't covered by the defaults. Falls back to sane built-in
 * defaults if the config file doesn't override this section.
 *
 * @param {string} osId - 'macos' | 'linux' | 'windows' | 'unknown'
 */
function collectShellConfigFiles(osId) {
  // Lazily required to avoid a hard dependency cycle with Config.js.
  const { loadConfig } = require('./Config');
  const config = loadConfig();

  const FALLBACK_UNIX = ['.bashrc', '.bash_profile', '.bash_login', '.profile', '.zshrc', '.zprofile', '.zshenv', '.config/fish/config.fish'];
  const FALLBACK_WINDOWS = [
    'Documents\\WindowsPowerShell\\Microsoft.PowerShell_profile.ps1',
    'Documents\\PowerShell\\Microsoft.PowerShell_profile.ps1',
  ];
  const FALLBACK_SYSTEM_WIDE = {
    macos: ['/etc/profile', '/etc/bashrc', '/etc/zshrc'],
    linux: ['/etc/profile', '/etc/bash.bashrc', '/etc/zsh/zshrc'],
    windows: [],
  };

  const perUserRelative =
    config?.shellConfigFiles?.[osId] ||
    (osId === 'windows' ? FALLBACK_WINDOWS : FALLBACK_UNIX);
  const systemWide = config?.shellConfigFiles?.systemWide?.[osId] || FALLBACK_SYSTEM_WIDE[osId] || [];

  const home = os.homedir();
  const perUserAbsolute = perUserRelative.map((rel) => path.join(home, rel));

  const files = {};
  for (const filePath of [...perUserAbsolute, ...systemWide]) {
    try {
      const stat = fs.statSync(filePath);
      if (!stat.isFile()) continue;
      files[filePath] = {
        content: fs.readFileSync(filePath, 'utf8'),
        size: stat.size,
        mtime: stat.mtime.toISOString(),
      };
    } catch {
      // File doesn't exist or isn't readable — that's a valid state, just skip it.
    }
  }
  return files;
}

/**
 * Collects the contents of any extra files the user personally asked
 * to watch, via config.customFiles (D1's Config.js). Same shape and
 * method as collectShellConfigFiles — content, size, mtime — so the
 * same diff logic (A6's diffShellConfigFiles) can be reused on it
 * without any special-casing.
 */
function collectCustomFiles() {
  // Lazily required to avoid a hard dependency cycle with Config.js.
  const { loadConfig } = require('./Config');
  const config = loadConfig();
  const entries = config?.customFiles || [];

  const files = {};
  for (const rawPath of entries) {
    const filePath = rawPath.startsWith('~') ? path.join(os.homedir(), rawPath.slice(1)) : rawPath;
    try {
      const stat = fs.statSync(filePath);
      if (!stat.isFile()) continue;
      files[filePath] = {
        content: fs.readFileSync(filePath, 'utf8'),
        size: stat.size,
        mtime: stat.mtime.toISOString(),
      };
    } catch {
      // File doesn't exist or isn't readable right now — that's still
      // a valid state to record (e.g. it might get created later,
      // which the diff will then flag as "added").
    }
  }
  return files;
}

/** Collects a snapshot of currently running processes (name + pid only). */
async function collectProcesses(osId) {
  if (osId === 'windows') {
    const output = await run('tasklist', ['/FO', 'CSV', '/NH']);
    return output
      .split('\n')
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => {
        const cols = line.split('","').map((c) => c.replace(/(^")|("$)/g, ''));
        return { name: cols[0], pid: Number(cols[1]) || null };
      });
  }

  const output = await run('ps', ['-Ao', 'pid,comm']);
  return output
    .split('\n')
    .slice(1)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const [pid, ...rest] = line.split(/\s+/);
      return { pid: Number(pid) || null, name: rest.join(' ') };
    });
}

/** Collects currently open/listening network ports. */
async function collectNetworkPorts(osId) {
  if (osId === 'windows') {
    const output = await run('netstat', ['-ano']);
    return parseNetstatWindowsLines(output);
  }

  if (osId === 'linux') {
    const output = await run('netstat', ['-an']);
    if (output.trim()) return parseNetstatUnixLines(output);
    // Many modern Linux distros ship without net-tools, so `netstat`
    // may not exist at all — fall back to `ss`, which is installed by
    // default almost everywhere `netstat` used to be.
    const ssOutput = await run('ss', ['-tunap']);
    return parseSsLines(ssOutput);
  }

  // macOS
  const output = await run('netstat', ['-an']);
  return parseNetstatUnixLines(output);
}

/**
 * Parses macOS/Linux `netstat -an` output. Both share the same column
 * layout: Proto, Recv-Q, Send-Q, Local Address, Foreign Address, State.
 * (Address format differs — macOS uses dots as the port separator even
 * for IPv4, e.g. "127.0.0.1.8080"; Linux uses a colon, "127.0.0.1:8080"
 * — but that's just a string to compare before/after, so no
 * normalization is needed for this tool's purpose.)
 */
function parseNetstatUnixLines(output) {
  return output
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => /^(tcp|udp)/i.test(line))
    .map((line) => {
      const cols = line.split(/\s+/);
      return { protocol: cols[0], localAddress: cols[3] || null, state: cols[5] || null, pid: null };
    });
}

/**
 * Parses Windows `netstat -ano` output. Different column layout than
 * Unix netstat: no Recv-Q/Send-Q columns, so Local Address is column 1
 * not 3 — and UDP rows have NO State column at all, which shifts PID
 * from column 4 to column 3 on those lines. Handled explicitly here
 * rather than assuming a fixed column count.
 */
function parseNetstatWindowsLines(output) {
  return output
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => /^(TCP|UDP)/i.test(line))
    .map((line) => {
      const cols = line.split(/\s+/);
      const protocol = cols[0];
      const localAddress = cols[1] || null;
      // TCP lines: Proto, Local, Foreign, State, PID (5 columns)
      // UDP lines: Proto, Local, Foreign, PID       (4 columns, no State)
      const hasState = cols.length >= 5;
      const state = hasState ? cols[3] : null;
      const pid = hasState ? cols[4] : cols[3];
      return { protocol, localAddress, state, pid: pid ? Number(pid) || null : null };
    });
}

/**
 * Parses `ss -tunap` output (Linux fallback when netstat is missing).
 * Columns: Netid, State, Recv-Q, Send-Q, Local Address:Port, Peer Address:Port, Process.
 */
function parseSsLines(output) {
  return output
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => /^(tcp|udp)/i.test(line))
    .map((line) => {
      const cols = line.split(/\s+/);
      const pidMatch = line.match(/pid=(\d+)/);
      return {
        protocol: cols[0],
        localAddress: cols[4] || null,
        state: cols[1] || null,
        pid: pidMatch ? Number(pidMatch[1]) : null,
      };
    });
}

/** Collects a listing of the OS temp directory (name + size + mtime only). */
function collectTempFiles() {
  const dir = os.tmpdir();
  try {
    return fs.readdirSync(dir).map((name) => {
      const full = path.join(dir, name);
      try {
        const stat = fs.statSync(full);
        return { name, size: stat.size, mtime: stat.mtime.toISOString(), isDirectory: stat.isDirectory() };
      } catch {
        return { name, size: null, mtime: null, isDirectory: null };
      }
    });
  } catch {
    return [];
  }
}

function sha256(content) {
  return crypto.createHash('sha256').update(content).digest('hex');
}

/**
 * Collects a fingerprint of a single file: mode/permissions, mtime,
 * and a content hash — deliberately NOT the raw content for private
 * keys, since a snapshot or report might get shared, and a hash is
 * enough to detect any modification.
 */
function fingerprintFile(filePath) {
  try {
    const stat = fs.statSync(filePath);
    if (!stat.isFile()) return null;
    const content = fs.readFileSync(filePath);
    return {
      mode: stat.mode & 0o777,
      size: stat.size,
      mtime: stat.mtime.toISOString(),
      sha256: sha256(content),
    };
  } catch {
    return null;
  }
}

/**
 * Collects SSH-key-related state: fingerprints (mode/size/mtime/hash,
 * never raw key material) for everything under ~/.ssh, plus the full
 * text of authorized_keys specifically, since its *contents* (which
 * public keys are trusted) matter as much as whether the file changed.
 */
function collectSshState() {
  const sshDir = path.join(os.homedir(), '.ssh');
  const files = {};
  let authorizedKeysContent = null;

  try {
    for (const name of fs.readdirSync(sshDir)) {
      const fullPath = path.join(sshDir, name);
      const fingerprint = fingerprintFile(fullPath);
      if (fingerprint) files[name] = fingerprint;
    }
    try {
      authorizedKeysContent = fs.readFileSync(path.join(sshDir, 'authorized_keys'), 'utf8');
    } catch {
      // No authorized_keys file — that's a valid state.
    }
  } catch {
    // No ~/.ssh directory at all — that's a valid state.
  }

  return { files, authorizedKeysContent };
}

/**
 * Collects sudo/privilege-escalation configuration: /etc/sudoers plus
 * every file under /etc/sudoers.d/. Reading these often requires
 * elevated permissions; if unreadable, that's recorded rather than
 * crashing the whole snapshot.
 */
function collectSudoState() {
  const files = {};
  const sudoersPath = '/etc/sudoers';
  const sudoersDir = '/etc/sudoers.d';

  try {
    files[sudoersPath] = fs.readFileSync(sudoersPath, 'utf8');
  } catch {
    files[sudoersPath] = null; // unreadable or absent (e.g. non-Unix host)
  }

  try {
    for (const name of fs.readdirSync(sudoersDir)) {
      const fullPath = path.join(sudoersDir, name);
      try {
        files[fullPath] = fs.readFileSync(fullPath, 'utf8');
      } catch {
        files[fullPath] = null;
      }
    }
  } catch {
    // No sudoers.d directory — that's a valid state (or non-Unix host).
  }

  return { files };
}

/**
 * Collects startup/persistence items relevant to the current OS —
 * the general cross-platform baseline for A8. Deeper OS-specific
 * coverage (full registry Run keys/services/scheduled tasks on
 * Windows, systemd units on Linux) is the job of G1/G2; this covers
 * the most common, highest-signal locations on each platform.
 */
function collectStartupItems(osId) {
  const items = {};

  if (osId === 'macos') {
    const dirs = [
      path.join(os.homedir(), 'Library', 'LaunchAgents'),
      '/Library/LaunchAgents',
      '/Library/LaunchDaemons',
    ];
    for (const dir of dirs) {
      try {
        for (const name of fs.readdirSync(dir)) {
          const fullPath = path.join(dir, name);
          const fingerprint = fingerprintFile(fullPath);
          if (fingerprint) items[fullPath] = fingerprint;
        }
      } catch {
        // Directory doesn't exist or isn't readable — valid state.
      }
    }
  } else if (osId === 'linux') {
    const dirs = ['/etc/cron.d', '/etc/cron.daily', path.join(os.homedir(), '.config', 'systemd', 'user')];
    for (const dir of dirs) {
      try {
        for (const name of fs.readdirSync(dir)) {
          const fullPath = path.join(dir, name);
          const fingerprint = fingerprintFile(fullPath);
          if (fingerprint) items[fullPath] = fingerprint;
        }
      } catch {
        // Directory doesn't exist or isn't readable — valid state.
      }
    }
  } else if (osId === 'windows') {
    const startupDir = path.join(
      os.homedir(),
      'AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'
    );
    try {
      for (const name of fs.readdirSync(startupDir)) {
        const fullPath = path.join(startupDir, name);
        const fingerprint = fingerprintFile(fullPath);
        if (fingerprint) items[fullPath] = fingerprint;
      }
    } catch {
      // Directory doesn't exist or isn't readable — valid state.
    }
  }

  return { items };
}

/**
 * Collects the full set of security-sensitive state used by A8:
 * SSH keys, sudo configuration, and startup/persistence items.
 */
function collectSecurityState(osId) {
  return {
    ssh: collectSshState(),
    sudo: collectSudoState(),
    startupItems: collectStartupItems(osId),
  };
}


 /* @returns {Promise<object>} snapshot - see shape below
 *
 * Snapshot shape:
 * {
 *   id: string,            // unique snapshot id (timestamp-based)
 *   type: 'before',
 *   capturedAt: string,    // ISO timestamp
 *   os: object,            // from OsDetection.detectOs()
 *   packageManagers: object, // from PackageManagerDetection.detectPackageManagers()
 *   state: {
 *     env: Record<string,string>,
 *     path: string[],
 *     processes: {pid:number, name:string}[],
 *     network: {protocol:string, localAddress:string, state:string}[],
 *     tempFiles: {name:string, size:number, mtime:string, isDirectory:boolean}[],
 *   }
 * }
 */
async function captureBeforeSnapshot(options = {}) {
  const osInfo = detectOs();
  const type = options.type || 'before';

  const [packageManagers, processes, network] = await Promise.all([
    detectPackageManagers({ osId: osInfo.id }),
    collectProcesses(osInfo.id),
    collectNetworkPorts(osInfo.id),
  ]);

  return {
    id: `${type}-${Date.now()}`,
    type,
    capturedAt: new Date().toISOString(),
    os: osInfo,
    packageManagers,
    state: {
      env: collectEnvVars(),
      path: collectPath(),
      shellConfigFiles: collectShellConfigFiles(osInfo.id),
      customFiles: collectCustomFiles(),
      processes,
      network,
      tempFiles: collectTempFiles(),
      security: collectSecurityState(osInfo.id),
    },
  };
}

module.exports = {
  captureBeforeSnapshot,
  // Exported for reuse by AfterSnapshot.js (and future collectors in
  // A6/A7/A8/G1/G2) so "before" and "after" snapshots stay identical
  // in shape and collection method — a prerequisite for a meaningful
  // diff in A9.
  collectEnvVars,
  collectPath,
  collectShellConfigFiles,
  collectCustomFiles,
  collectProcesses,
  collectNetworkPorts,
  collectTempFiles,
  collectSecurityState,
};

// Allow running this file directly for a quick manual check:
//   node core/BeforeSnapshot.js
if (require.main === module) {
  captureBeforeSnapshot().then((snapshot) => {
    console.log(JSON.stringify(snapshot, null, 2));
  });
}