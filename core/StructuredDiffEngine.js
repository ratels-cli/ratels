// core/StructuredDiffEngine.js
//
// User Story A9 (5 pts · High)
// As a developer, I want the tool to compute a structured diff
// between my before/after snapshots, so that I get a clear picture of
// what changed instead of two disconnected dumps.
//
// This is the top-level engine: it takes a before/after snapshot pair
// (or a full bundle from InstallMonitor.js) and combines the three
// specialized diffs — A6 (env/PATH/shell), A7 (network/process/temp),
// and A8 (security flagging) — into one unified, structured report.
// B1 (plain-text report) and B4 (--json output) both build on top of
// what this module returns.

'use strict';

const { diffEnvPathShell } = require('./EnvPathShellDiff');
const { diffNetworkProcessTemp } = require('./NetworkProcessTempDiff');
const { flagSecurityChanges } = require('./SecurityFlagsDiff');

/**
 * Computes an overall risk level for the run, derived from the
 * highest-severity security finding (A8) and whether A6/A7 flagged
 * anything suspicious. Security findings dominate, since a single
 * new SSH key matters more than a dozen harmless temp files.
 */
function computeOverallRisk({ security, envPathShell, networkProcessTemp }) {
  if (security.counts.critical > 0) return 'critical';
  if (security.counts.high > 0) return 'high';
  if (envPathShell.hasSuspiciousChanges || networkProcessTemp.hasSuspiciousChanges) return 'medium';
  if (security.counts.medium > 0 || security.counts.low > 0) return 'low';
  return 'none';
}

/**
 * Computes the full structured diff between a before/after snapshot
 * pair. Accepts either two snapshot objects, or a single bundle object
 * shaped like InstallMonitor.js's output ({ before, after, ... }).
 *
 * @param {object} before - snapshot from captureBeforeSnapshot(), OR a full
 *   InstallMonitor bundle if `after` is omitted.
 * @param {object} [after] - snapshot from captureAfterSnapshot()
 * @returns {{
 *   meta: {
 *     beforeId: string, afterId: string,
 *     beforeCapturedAt: string, afterCapturedAt: string,
 *     os: object, command: string|null, args: string[]|null,
 *   },
 *   envPathShell: ReturnType<import('./EnvPathShellDiff').diffEnvPathShell>,
 *   networkProcessTemp: ReturnType<import('./NetworkProcessTempDiff').diffNetworkProcessTemp>,
 *   security: ReturnType<import('./SecurityFlagsDiff').flagSecurityChanges>,
 *   overallRisk: 'none'|'low'|'medium'|'high'|'critical',
 *   summary: string[],  // short human-readable bullet points, for B1's report
 * }}
 */
function computeStructuredDiff(before, after) {
  // Support being handed an InstallMonitor bundle directly.
  let bundleMeta = { command: null, args: null };
  if (!after && before && before.before && before.after) {
    bundleMeta = { command: before.command || null, args: before.args || null };
    after = before.after;
    before = before.before;
  }

  const envPathShell = diffEnvPathShell(before, after);
  const networkProcessTemp = diffNetworkProcessTemp(before, after);
  const security = flagSecurityChanges(before, after);

  const overallRisk = computeOverallRisk({ security, envPathShell, networkProcessTemp });

  const summary = buildSummary({ envPathShell, networkProcessTemp, security });

  return {
    meta: {
      beforeId: before?.id || null,
      afterId: after?.id || null,
      beforeCapturedAt: before?.capturedAt || null,
      afterCapturedAt: after?.capturedAt || null,
      os: after?.os || before?.os || null,
      command: bundleMeta.command,
      args: bundleMeta.args,
    },
    envPathShell,
    networkProcessTemp,
    security,
    overallRisk,
    summary,
  };
}

/** Builds a short list of plain-English bullet points summarizing the diff. */
function buildSummary({ envPathShell, networkProcessTemp, security }) {
  const lines = [];

  if (security.findings.length > 0) {
    lines.push(`${security.findings.length} security-relevant finding(s), highest severity: ${security.highestSeverity}.`);
  } else {
    lines.push('No security-relevant findings (SSH, sudo, startup items unchanged).');
  }

  const envChanges = Object.keys(envPathShell.env.added).length + Object.keys(envPathShell.env.changed).length + Object.keys(envPathShell.env.removed).length;
  if (envChanges > 0) lines.push(`${envChanges} environment variable(s) added/changed/removed.`);
  if (envPathShell.path.reordered) lines.push('PATH order changed.');
  if (envPathShell.path.prependedEntries.length > 0) lines.push(`${envPathShell.path.prependedEntries.length} new PATH entr(y/ies) inserted ahead of existing ones.`);
  if (envPathShell.shellConfigFiles.changed.length > 0) lines.push(`${envPathShell.shellConfigFiles.changed.length} shell config file(s) modified.`);

  const customChanges = envPathShell.customFiles.added.length + envPathShell.customFiles.removed.length + envPathShell.customFiles.changed.length;
  if (customChanges > 0) lines.push(`${customChanges} custom watched file(s) changed.`);

  if (networkProcessTemp.network.opened.length > 0) lines.push(`${networkProcessTemp.network.opened.length} new network port(s) opened.`);
  if (networkProcessTemp.processes.started.length > 0) lines.push(`${networkProcessTemp.processes.started.length} new process name(s) started.`);
  if (networkProcessTemp.tempFiles.added.length > 0) lines.push(`${networkProcessTemp.tempFiles.added.length} new temp file(s) created.`);

  return lines;
}

module.exports = {
  computeStructuredDiff,
};

// Allow running this file directly against either:
//   - two saved snapshot JSON files:      node core/StructuredDiffEngine.js before.json after.json
//   - one saved InstallMonitor bundle:    node core/StructuredDiffEngine.js bundle.json
if (require.main === module) {
  const fs = require('fs');
  const [firstPath, secondPath] = process.argv.slice(2);

  if (!firstPath) {
    console.error('Usage: node core/StructuredDiffEngine.js <before.json> <after.json>');
    console.error('   or: node core/StructuredDiffEngine.js <bundle.json>');
    process.exit(1);
  }

  const first = JSON.parse(fs.readFileSync(firstPath, 'utf8'));
  const second = secondPath ? JSON.parse(fs.readFileSync(secondPath, 'utf8')) : undefined;

  console.log(JSON.stringify(computeStructuredDiff(first, second), null, 2));
}