// core/PackageManagerDetection.js
//
// User Story A2 (3 pts · High)
// As a developer, I want the tool to detect which package managers are
// installed on my machine (npm, pip, pipx, brew, apt, winget, choco),
// so that it knows which install commands to monitor.

'use strict';

const { execFile } = require('child_process');
const { detectOs, SUPPORTED_OS } = require('./OsDetection');

/**
 * Registry of package managers we know how to detect, and which
 * OS(es) each one is relevant on. `versionArgs` is used to both
 * (a) confirm the binary actually works, and (b) capture its version.
 */
const PACKAGE_MANAGERS = Object.freeze({
  npm: { command: 'npm', versionArgs: ['--version'], os: [SUPPORTED_OS.WINDOWS, SUPPORTED_OS.MACOS, SUPPORTED_OS.LINUX] },
  pip: { command: 'pip', versionArgs: ['--version'], os: [SUPPORTED_OS.WINDOWS, SUPPORTED_OS.MACOS, SUPPORTED_OS.LINUX] },
  pipx: { command: 'pipx', versionArgs: ['--version'], os: [SUPPORTED_OS.WINDOWS, SUPPORTED_OS.MACOS, SUPPORTED_OS.LINUX] },
  brew: { command: 'brew', versionArgs: ['--version'], os: [SUPPORTED_OS.MACOS, SUPPORTED_OS.LINUX] },
  apt: { command: 'apt', versionArgs: ['--version'], os: [SUPPORTED_OS.LINUX] },
  winget: { command: 'winget', versionArgs: ['--version'], os: [SUPPORTED_OS.WINDOWS] },
  choco: { command: 'choco', versionArgs: ['--version'], os: [SUPPORTED_OS.WINDOWS] },
});

/**
 * Runs `<command> <versionArgs>` and resolves with the trimmed stdout,
 * or null if the binary isn't found / errors out. Never rejects.
 */
function tryGetVersion(command, versionArgs) {
  return new Promise((resolve) => {
    execFile(command, versionArgs, { timeout: 5000, windowsHide: true }, (error, stdout) => {
      if (error) {
        resolve(null);
        return;
      }
      resolve(String(stdout).trim().split('\n')[0]);
    });
  });
}

/**
 * Detects which package managers are installed on the current machine.
 * Only checks managers relevant to the detected OS (e.g. skips `apt`
 * on Windows, skips `winget`/`choco` on macOS/Linux).
 *
 * @param {object} [options]
 * @param {string} [options.osId] - override detected OS id (mainly for tests)
 * @returns {Promise<{
 *   os: string,
 *   available: string[],                 // ids of detected managers, e.g. ['npm', 'brew']
 *   details: Record<string, {installed: boolean, version: string|null}>
 * }>}
 */
async function detectPackageManagers(options = {}) {
  const osId = options.osId || detectOs().id;

  const candidates = Object.entries(PACKAGE_MANAGERS).filter(
    ([, def]) => def.os.includes(osId)
  );

  const results = await Promise.all(
    candidates.map(async ([name, def]) => {
      const version = await tryGetVersion(def.command, def.versionArgs);
      return [name, { installed: version !== null, version }];
    })
  );

  const details = Object.fromEntries(results);
  const available = Object.keys(details).filter((name) => details[name].installed);

  return { os: osId, available, details };
}

module.exports = {
  PACKAGE_MANAGERS,
  detectPackageManagers,
};

// Allow running this file directly for a quick manual check:
//   node core/PackageManagerDetection.js
if (require.main === module) {
  detectPackageManagers().then((result) => {
    console.log(JSON.stringify(result, null, 2));
  });
}