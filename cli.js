#!/usr/bin/env node
// cli.js
//
// User Story B2 (3 pts · High) — CLI trigger + view report
// User Story B4 (3 pts · Medium) — --json output mode
// User Story B5 (1 pt · Medium) — --help output
//
// This is the single entry point: it wires together A4 (install
// monitor), A9 (structured diff engine), B1 (plain-text report), and
// B3 (local snapshot/report storage) into one command.
//
// Usage:
//   node cli.js [options] <command> [args...]
//
// Options:
//   --json         Print the structured diff report as JSON on stdout
//                  instead of the plain-text report (B4). All status
//                  messages ("Monitoring: ...", "Saved snapshot...",
//                  etc.) still go to stderr either way, so stdout is
//                  clean JSON — safe to pipe into `jq`, a file, or a
//                  CI step.
//   -h, --help     Show this help and exit (B5).
//
// Examples:
//   node cli.js npm install left-pad
//   node cli.js --json npm install left-pad > report.json
//   node cli.js pip install requests
//
// Note: only flags listed above, appearing BEFORE the wrapped command,
// are treated as cli.js's own options. Everything from the first
// non-flag argument onward — including any flags in it, like
// `--save` in `npm install --save left-pad` — is passed straight
// through to the wrapped command untouched.

'use strict';

const { monitorInstall } = require('./core/InstallMonitor');
const { computeStructuredDiff } = require('./core/StructuredDiffEngine');
const { renderPlainTextReport } = require('./core/PlainTextReport');
const { saveSnapshotPair, saveReport } = require('./core/SnapshotStore');

const KNOWN_FLAGS = new Set(['--json', '--help', '-h']);

const HELP_TEXT = `
Supply Chain Security Monitor

Usage:
  node cli.js [options] <command> [args...]

Wraps a package-install command, capturing a before/after snapshot of
your system and reporting anything that changed — env vars, PATH,
shell config, network ports, processes, temp files, and
security-sensitive items like SSH keys, sudoers, and startup entries.

Options:
  --json         Print the report as JSON on stdout instead of plain
                 text. Status messages still go to stderr, so stdout
                 is clean JSON for piping into other tools or CI.
  -h, --help     Show this help and exit.

Examples:
  node cli.js npm install left-pad
  node cli.js --json npm install left-pad > report.json
  node cli.js pip install requests

Exit codes:
  0   Completed, no high/critical risk findings.
  1   The tool itself errored (e.g. bad usage, unexpected crash).
  2   Completed, but risk was HIGH or CRITICAL — check the report.

Every snapshot and report is also saved locally for later review
(see ~/.pkg_monitor/snapshots and ~/.pkg_monitor/reports).
`.trim();

/**
 * Splits argv into { flags, command, args }. Only flags appearing
 * BEFORE the first non-flag token are treated as ours; everything
 * from that point on (including flags) belongs to the wrapped command.
 */
function parseArgv(argv) {
  const flags = new Set();
  let i = 0;

  while (i < argv.length && argv[i].startsWith('-')) {
    if (KNOWN_FLAGS.has(argv[i])) {
      flags.add(argv[i]);
      i++;
    } else {
      // Unknown leading flag — stop treating things as our own flags
      // rather than silently swallowing something meant for the
      // wrapped command.
      break;
    }
  }

  const [command, ...args] = argv.slice(i);
  return { flags, command, args };
}

async function main() {
  const { flags, command, args } = parseArgv(process.argv.slice(2));

  if (flags.has('--help') || flags.has('-h')) {
    console.log(HELP_TEXT);
    return;
  }

  if (!command) {
    console.error(HELP_TEXT);
    process.exit(1);
  }

  const jsonMode = flags.has('--json');

  console.error(`Monitoring: ${command} ${args.join(' ')}\n`);

  // A4 — before snapshot -> run command -> after snapshot.
  const bundle = await monitorInstall(command, args);

  if (bundle.error) {
    console.error(`Command failed to launch: ${bundle.error}`);
  }

  // A9 — combine A6/A7/A8 into one structured diff.
  const report = computeStructuredDiff(bundle);

  // B1 — render it as plain text (used for the saved .txt report either way).
  const text = renderPlainTextReport(report);

  // B3 — save the audit trail (snapshots + report, JSON + text).
  const { beforePath, afterPath } = saveSnapshotPair(bundle.before, bundle.after);
  const { jsonPath, textPath } = saveReport(report, text);

  // B4 — --json prints the structured report on stdout instead of
  // the plain-text version; everything else stays on stderr so stdout
  // is safe to pipe straight into `jq`, a file, or a CI step.
  if (jsonMode) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log('\n' + text);
  }

  console.error(`\nSaved before snapshot: ${beforePath}`);
  console.error(`Saved after snapshot:  ${afterPath}`);
  console.error(`Saved report (json):   ${jsonPath}`);
  console.error(`Saved report (text):   ${textPath}`);

  // Non-zero exit when something risky was found, so this plays nicely
  // in a CI pipeline (C3) without extra flags.
  if (report.overallRisk === 'critical' || report.overallRisk === 'high') {
    process.exitCode = 2;
  }
}

main().catch((err) => {
  console.error('Unexpected error:', err);
  process.exit(1);
});