// core/SecurityFlagsDiff.js
//
// User Story A8 (8 pts · High)
// As a developer, I want the tool to flag security-relevant changes
// like SSH key modifications, sudo permission changes, and new
// startup items, so that I'm alerted to the most dangerous kinds of
// tampering first.
//
// Consumes `state.security` from a before/after snapshot pair
// (BeforeSnapshot.js / AfterSnapshot.js) and produces a flat list of
// severity-ranked findings — the "most dangerous first" view A9 will
// surface at the top of the combined report.

'use strict';

const SEVERITY = Object.freeze({
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
});

/** Diffs a { path: fingerprint } map by comparing sha256 hashes. */
function diffFingerprintMap(before = {}, after = {}) {
  const added = [];
  const removed = [];
  const modified = [];

  for (const key of Object.keys(after)) {
    if (!(key in before)) {
      added.push(key);
    } else if (before[key]?.sha256 !== after[key]?.sha256 || before[key]?.mode !== after[key]?.mode) {
      modified.push({ path: key, before: before[key], after: after[key] });
    }
  }
  for (const key of Object.keys(before)) {
    if (!(key in after)) removed.push(key);
  }

  return { added, removed, modified };
}

/**
 * Flags SSH-related changes: any new/removed/modified key file is
 * CRITICAL (this is the single most common persistence mechanism for
 * "I installed a package and now there's a backdoor" attacks), and
 * any change to authorized_keys content is CRITICAL and called out
 * with the actual added/removed lines, since *which* key was trusted
 * matters, not just that the file touched.
 */
function flagSshChanges(before = {}, after = {}) {
  const findings = [];
  const fileDiff = diffFingerprintMap(before.files, after.files);

  for (const p of fileDiff.added) {
    findings.push({ severity: SEVERITY.CRITICAL, category: 'ssh', message: `New SSH key material appeared: ${p}` });
  }
  for (const p of fileDiff.removed) {
    findings.push({ severity: SEVERITY.HIGH, category: 'ssh', message: `SSH key material was removed: ${p}` });
  }
  for (const m of fileDiff.modified) {
    findings.push({ severity: SEVERITY.CRITICAL, category: 'ssh', message: `SSH key file was modified: ${m.path}` });
  }

  const beforeAuth = before.authorizedKeysContent;
  const afterAuth = after.authorizedKeysContent;
  if (beforeAuth !== afterAuth) {
    const beforeLines = new Set((beforeAuth || '').split('\n').filter((l) => l.trim()));
    const afterLines = new Set((afterAuth || '').split('\n').filter((l) => l.trim()));
    const addedLines = [...afterLines].filter((l) => !beforeLines.has(l));
    const removedLines = [...beforeLines].filter((l) => !afterLines.has(l));
    if (addedLines.length > 0) {
      findings.push({
        severity: SEVERITY.CRITICAL,
        category: 'ssh',
        message: `New key(s) trusted in authorized_keys (${addedLines.length} line(s) added)`,
        detail: addedLines,
      });
    }
    if (removedLines.length > 0) {
      findings.push({
        severity: SEVERITY.MEDIUM,
        category: 'ssh',
        message: `Key(s) removed from authorized_keys (${removedLines.length} line(s) removed)`,
        detail: removedLines,
      });
    }
  }

  return findings;
}

/**
 * Flags sudo/privilege changes: any change to /etc/sudoers or any
 * file under /etc/sudoers.d/ is CRITICAL, since this is literally the
 * configuration for who can run what as root.
 */
function flagSudoChanges(before = {}, after = {}) {
  const findings = [];
  const beforeFiles = before.files || {};
  const afterFiles = after.files || {};

  const allPaths = new Set([...Object.keys(beforeFiles), ...Object.keys(afterFiles)]);
  for (const filePath of allPaths) {
    const beforeContent = beforeFiles[filePath];
    const afterContent = afterFiles[filePath];
    if (beforeContent === afterContent) continue;

    if (beforeContent == null && afterContent != null) {
      findings.push({ severity: SEVERITY.CRITICAL, category: 'sudo', message: `New sudoers file created: ${filePath}` });
    } else if (beforeContent != null && afterContent == null) {
      findings.push({ severity: SEVERITY.HIGH, category: 'sudo', message: `Sudoers file removed or became unreadable: ${filePath}` });
    } else {
      findings.push({ severity: SEVERITY.CRITICAL, category: 'sudo', message: `Sudoers configuration changed: ${filePath}` });
    }
  }

  return findings;
}

/**
 * Flags new/removed/modified startup (persistence) items. New items
 * are HIGH — this is the classic way malware survives a reboot.
 */
function flagStartupItemChanges(before = {}, after = {}) {
  const findings = [];
  const itemDiff = diffFingerprintMap(before.items, after.items);

  for (const p of itemDiff.added) {
    findings.push({ severity: SEVERITY.HIGH, category: 'startup', message: `New startup/persistence item: ${p}` });
  }
  for (const p of itemDiff.removed) {
    findings.push({ severity: SEVERITY.LOW, category: 'startup', message: `Startup item removed: ${p}` });
  }
  for (const m of itemDiff.modified) {
    findings.push({ severity: SEVERITY.HIGH, category: 'startup', message: `Startup item modified: ${m.path}` });
  }

  return findings;
}

/**
 * Flags changes to Windows registry Run/RunOnce keys (G1). Any new
 * entry is CRITICAL — this is the single most common Windows
 * persistence mechanism, directly equivalent to a new LaunchAgent on
 * macOS or a new systemd unit on Linux. A changed value (same value
 * name, different command/path) is just as critical, since that's
 * exactly how a legitimate autorun entry gets hijacked to point at
 * something malicious instead.
 */
function flagRegistryRunKeyChanges(before = {}, after = {}) {
  const findings = [];
  const allKeys = new Set([...Object.keys(before), ...Object.keys(after)]);

  for (const key of allKeys) {
    const beforeValue = before[key];
    const afterValue = after[key];
    if (beforeValue === afterValue) continue;

    if (beforeValue === undefined) {
      findings.push({ severity: SEVERITY.CRITICAL, category: 'windows-registry', message: `New registry autorun entry: ${key} -> ${afterValue}` });
    } else if (afterValue === undefined) {
      findings.push({ severity: SEVERITY.MEDIUM, category: 'windows-registry', message: `Registry autorun entry removed: ${key}` });
    } else {
      findings.push({
        severity: SEVERITY.CRITICAL,
        category: 'windows-registry',
        message: `Registry autorun entry changed: ${key} ("${beforeValue}" -> "${afterValue}")`,
      });
    }
  }

  return findings;
}

/**
 * Flags changes to Windows services (G1). A brand-new service is
 * HIGH — malware commonly installs itself as a service to survive
 * reboots and run with elevated privileges. An existing service whose
 * StartMode flips toward "Auto" is also worth flagging, since that's
 * a common way to convert an already-installed-but-dormant service
 * into a persistence mechanism without technically "adding" anything.
 */
function flagServiceChanges(before = {}, after = {}) {
  const findings = [];
  const allNames = new Set([...Object.keys(before), ...Object.keys(after)]);

  for (const name of allNames) {
    const beforeSvc = before[name];
    const afterSvc = after[name];

    if (!beforeSvc && afterSvc) {
      findings.push({ severity: SEVERITY.HIGH, category: 'windows-service', message: `New Windows service installed: ${name} (${afterSvc.startType}, ${afterSvc.status})` });
      continue;
    }
    if (beforeSvc && !afterSvc) {
      findings.push({ severity: SEVERITY.LOW, category: 'windows-service', message: `Windows service removed: ${name}` });
      continue;
    }
    if (beforeSvc.startType !== afterSvc.startType) {
      const gotMoreAggressive = afterSvc.startType === 'Auto' && beforeSvc.startType !== 'Auto';
      findings.push({
        severity: gotMoreAggressive ? SEVERITY.MEDIUM : SEVERITY.LOW,
        category: 'windows-service',
        message: `Service "${name}" start type changed: ${beforeSvc.startType} -> ${afterSvc.startType}`,
      });
    }
  }

  return findings;
}

/**
 * Flags changes to Windows scheduled tasks (G1) — the modern
 * equivalent of cron, and a common way for both legitimate installers
 * and malware to re-trigger something on a schedule or at logon.
 */
function flagScheduledTaskChanges(before = {}, after = {}) {
  const findings = [];
  const allNames = new Set([...Object.keys(before), ...Object.keys(after)]);

  for (const name of allNames) {
    const beforeTask = before[name];
    const afterTask = after[name];

    if (!beforeTask && afterTask) {
      findings.push({ severity: SEVERITY.HIGH, category: 'windows-task', message: `New scheduled task created: ${name} (${afterTask.state})` });
    } else if (beforeTask && !afterTask) {
      findings.push({ severity: SEVERITY.LOW, category: 'windows-task', message: `Scheduled task removed: ${name}` });
    } else if (beforeTask.state !== afterTask.state) {
      findings.push({ severity: SEVERITY.LOW, category: 'windows-task', message: `Scheduled task "${name}" state changed: ${beforeTask.state} -> ${afterTask.state}` });
    }
  }

  return findings;
}

/**
 * Runs all three Windows-specific G1 checks together. Returns an
 * empty array on non-Windows hosts, or if the data wasn't collected
 * for any reason (e.g. PowerShell unavailable).
 */
function flagWindowsPersistenceChanges(before, after) {
  if (!before && !after) return [];
  const b = before || {};
  const a = after || {};

  return [
    ...flagRegistryRunKeyChanges(b.registryRunKeys, a.registryRunKeys),
    ...flagServiceChanges(b.services, a.services),
    ...flagScheduledTaskChanges(b.scheduledTasks, a.scheduledTasks),
  ];
}

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

/**
 * Runs the full A8 flagging pass against a before/after snapshot pair
 * from BeforeSnapshot.js / AfterSnapshot.js.
 *
 * @param {object} before - snapshot from captureBeforeSnapshot()
 * @param {object} after - snapshot from captureAfterSnapshot()
 * @returns {{
 *   findings: Array<{severity: string, category: string, message: string, detail?: string[]}>,
 *   highestSeverity: string|null,
 *   counts: Record<string, number>,
 * }}
 */
function flagSecurityChanges(before, after) {
  const beforeSecurity = before?.state?.security || {};
  const afterSecurity = after?.state?.security || {};

  const findings = [
    ...flagSshChanges(beforeSecurity.ssh, afterSecurity.ssh),
    ...flagSudoChanges(beforeSecurity.sudo, afterSecurity.sudo),
    ...flagStartupItemChanges(beforeSecurity.startupItems, afterSecurity.startupItems),
    ...flagWindowsPersistenceChanges(beforeSecurity.windows, afterSecurity.windows),
  ].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) counts[f.severity]++;

  const highestSeverity = findings.length > 0 ? findings[0].severity : null;

  return { findings, highestSeverity, counts };
}

module.exports = {
  SEVERITY,
  flagSshChanges,
  flagSudoChanges,
  flagStartupItemChanges,
  flagRegistryRunKeyChanges,
  flagServiceChanges,
  flagScheduledTaskChanges,
  flagWindowsPersistenceChanges,
  flagSecurityChanges,
};

// Allow running this file directly against two saved snapshot JSON files:
//   node core/SecurityFlagsDiff.js before.json after.json
if (require.main === module) {
  const fs = require('fs');
  const [beforePath, afterPath] = process.argv.slice(2);

  if (!beforePath || !afterPath) {
    console.error('Usage: node core/SecurityFlagsDiff.js <before.json> <after.json>');
    process.exit(1);
  }

  const before = JSON.parse(fs.readFileSync(beforePath, 'utf8'));
  const after = JSON.parse(fs.readFileSync(afterPath, 'utf8'));

  console.log(JSON.stringify(flagSecurityChanges(before, after), null, 2));
}