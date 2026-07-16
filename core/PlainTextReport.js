// core/PlainTextReport.js
//
// User Story B1 (3 pts · High)
// As a developer, I want a plain-text report summarizing all detected
// changes, so that I can quickly understand what happened without
// parsing raw data.
//
// Renders the structured diff produced by StructuredDiffEngine.js
// (A9) into a readable text report. B3 saves this alongside the JSON
// form; B2's CLI prints it straight to the terminal.

'use strict';

const SEVERITY_LABEL = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW',
};

function line(char = '-', width = 60) {
  return char.repeat(width);
}

function section(title) {
  return `\n${title}\n${line('-', title.length)}`;
}

/**
 * Renders a full structured diff (from computeStructuredDiff()) as a
 * plain-text report.
 *
 * @param {object} report - from computeStructuredDiff()
 * @returns {string}
 */
function renderPlainTextReport(report) {
  const out = [];

  out.push(line('='));
  out.push('SUPPLY CHAIN SECURITY MONITOR - INSTALL REPORT');
  out.push(line('='));

  const meta = report.meta || {};
  if (meta.command) {
    out.push(`Command:      ${meta.command} ${(meta.args || []).join(' ')}`.trim());
  }
  out.push(`OS:           ${meta.os?.platform || 'unknown'} (${meta.os?.arch || 'unknown'})`);
  out.push(`Before:       ${meta.beforeId || 'n/a'}  (${meta.beforeCapturedAt || 'n/a'})`);
  out.push(`After:        ${meta.afterId || 'n/a'}  (${meta.afterCapturedAt || 'n/a'})`);
  out.push(`Overall risk: ${(report.overallRisk || 'none').toUpperCase()}`);

  out.push(section('SUMMARY'));
  for (const item of report.summary || []) {
    out.push(`  - ${item}`);
  }

  out.push(section('SECURITY FINDINGS (SSH / sudo / startup items)'));
  const findings = report.security?.findings || [];
  if (findings.length === 0) {
    out.push('  No security-relevant findings.');
  } else {
    for (const f of findings) {
      out.push(`  [${SEVERITY_LABEL[f.severity] || f.severity.toUpperCase()}] (${f.category}) ${f.message}`);
      if (f.detail && f.detail.length > 0) {
        for (const d of f.detail) out.push(`      + ${d}`);
      }
    }
  }

  out.push(section('ENVIRONMENT / PATH / SHELL CONFIG'));
  const env = report.envPathShell?.env || { added: {}, removed: {}, changed: {} };
  const envAdded = Object.keys(env.added);
  const envRemoved = Object.keys(env.removed);
  const envChanged = Object.keys(env.changed);
  if (envAdded.length === 0 && envRemoved.length === 0 && envChanged.length === 0) {
    out.push('  No environment variable changes.');
  } else {
    for (const k of envAdded) out.push(`  + ${k}=${env.added[k]}`);
    for (const k of envRemoved) out.push(`  - ${k}`);
    for (const k of envChanged) out.push(`  ~ ${k}: "${env.changed[k].before}" -> "${env.changed[k].after}"`);
  }

  const pathDiff = report.envPathShell?.path || {};
  out.push('');
  out.push(`  PATH reordered: ${pathDiff.reordered ? 'YES' : 'no'}`);
  if ((pathDiff.prependedEntries || []).length > 0) {
    out.push(`  PATH entries prepended (highest risk):`);
    for (const p of pathDiff.prependedEntries) out.push(`      + ${p}`);
  }
  if ((pathDiff.added || []).length > 0) {
    out.push(`  PATH entries added:`);
    for (const p of pathDiff.added) out.push(`      + ${p}`);
  }
  if ((pathDiff.removed || []).length > 0) {
    out.push(`  PATH entries removed:`);
    for (const p of pathDiff.removed) out.push(`      - ${p}`);
  }

  const shellFiles = report.envPathShell?.shellConfigFiles || { added: [], removed: [], changed: [] };
  if (shellFiles.added.length || shellFiles.removed.length || shellFiles.changed.length) {
    out.push('');
    out.push('  Shell config files:');
    for (const p of shellFiles.added) out.push(`      + created: ${p}`);
    for (const p of shellFiles.removed) out.push(`      - removed: ${p}`);
    for (const f of shellFiles.changed) {
      out.push(`      ~ modified: ${f.path}${f.suspicious ? '  [SUSPICIOUS]' : ''}`);
    }
  }

  const customFiles = report.envPathShell?.customFiles || { added: [], removed: [], changed: [] };
  if (customFiles.added.length || customFiles.removed.length || customFiles.changed.length) {
    out.push('');
    out.push('  Custom watched files (from config.customFiles):');
    for (const p of customFiles.added) out.push(`      + created: ${p}`);
    for (const p of customFiles.removed) out.push(`      - removed: ${p}`);
    for (const f of customFiles.changed) {
      out.push(`      ~ modified: ${f.path}  [WATCHED]`);
      for (const l of f.addedLines) out.push(`          + ${l}`);
      for (const l of f.removedLines) out.push(`          - ${l}`);
    }
  }

  out.push(section('NETWORK / PROCESSES / TEMP FILES'));
  const netDiff = report.networkProcessTemp?.network || { opened: [], closed: [] };
  const procDiff = report.networkProcessTemp?.processes || { started: [], stopped: [], countChanged: [] };
  const tempDiff = report.networkProcessTemp?.tempFiles || { added: [], removed: [], modified: [] };

  if (netDiff.opened.length === 0 && netDiff.closed.length === 0) {
    out.push('  No network port changes.');
  } else {
    for (const p of netDiff.opened) out.push(`  + opened: ${p.protocol} ${p.localAddress} (${p.state || 'n/a'})`);
    for (const p of netDiff.closed) out.push(`  - closed: ${p.protocol} ${p.localAddress}`);
  }

  out.push('');
  if (procDiff.started.length === 0 && procDiff.stopped.length === 0 && procDiff.countChanged.length === 0) {
    out.push('  No process changes.');
  } else {
    for (const p of procDiff.started) out.push(`  + started: ${p.name} (pid ${p.pid})`);
    for (const p of procDiff.stopped) out.push(`  - stopped: ${p.name}`);
    for (const p of procDiff.countChanged) out.push(`  ~ ${p.name}: ${p.before} -> ${p.after} instances`);
  }

  out.push('');
  if (tempDiff.added.length === 0 && tempDiff.removed.length === 0 && tempDiff.modified.length === 0) {
    out.push('  No temp file changes.');
  } else {
    for (const f of tempDiff.added) out.push(`  + ${f.name} (${f.size} bytes)`);
    for (const f of tempDiff.removed) out.push(`  - ${f.name}`);
    for (const f of tempDiff.modified) out.push(`  ~ ${f.name} (size ${f.before.size} -> ${f.after.size})`);
  }

  out.push('\n' + line('='));

  return out.join('\n');
}

module.exports = {
  renderPlainTextReport,
};

// Allow running this file directly against a saved structured-diff
// report JSON (from StructuredDiffEngine.js):
//   node core/PlainTextReport.js report.json
if (require.main === module) {
  const fs = require('fs');
  const [reportPath] = process.argv.slice(2);

  if (!reportPath) {
    console.error('Usage: node core/PlainTextReport.js <report.json>');
    process.exit(1);
  }

  const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
  console.log(renderPlainTextReport(report));
}