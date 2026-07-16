#!/usr/bin/env node
// cli.js
//
// User Story B2 (3 pts · High)
// As a developer, I want a CLI application to trigger a monitored
// install and view the resulting report, so that I have one simple
// command to run.
//
// This is the single entry point: it wires together A4 (install
// monitor), A9 (structured diff engine), B1 (plain-text report), and
// B3 (local snapshot/report storage) into one command.
//
// Usage:
//   node cli.js <command> [args...]
//   node cli.js npm install left-pad
//   node cli.js pip install requests

'use strict';

const { monitorInstall } = require('./core/InstallMonitor');
const { computeStructuredDiff } = require('./core/StructuredDiffEngine');
const { renderPlainTextReport } = require('./core/PlainTextReport');
const { saveSnapshotPair, saveReport } = require('./core/SnapshotStore');

async function main() {
  const [command, ...args] = process.argv.slice(2);

  if (!command) {
    console.error('Usage: node cli.js <command> [args...]');
    console.error('Example: node cli.js npm install left-pad');
    process.exit(1);
  }

  console.error(`Monitoring: ${command} ${args.join(' ')}\n`);

  // A4 — before snapshot -> run command -> after snapshot.
  const bundle = await monitorInstall(command, args);

  if (bundle.error) {
    console.error(`Command failed to launch: ${bundle.error}`);
  }

  // A9 — combine A6/A7/A8 into one structured diff.
  const report = computeStructuredDiff(bundle);

  // B1 — render it as plain text.
  const text = renderPlainTextReport(report);

  // B3 — save the audit trail (snapshots + report, JSON + text).
  const { beforePath, afterPath } = saveSnapshotPair(bundle.before, bundle.after);
  const { jsonPath, textPath } = saveReport(report, text);

  console.log('\n' + text);

  console.error(`\nSaved before snapshot: ${beforePath}`);
  console.error(`Saved after snapshot:  ${afterPath}`);
  console.error(`Saved report (json):   ${jsonPath}`);
  console.error(`Saved report (text):   ${textPath}`);

  // Non-zero exit when something risky was found, so this plays nicely
  // in a CI pipeline (B4/C3) without extra flags.
  if (report.overallRisk === 'critical' || report.overallRisk === 'high') {
    process.exitCode = 2;
  }
}

main().catch((err) => {
  console.error('Unexpected error:', err);
  process.exit(1);
});