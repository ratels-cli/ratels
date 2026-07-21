// core/FullScan.js
//
// User Story B6 (5 pts · High)
// As a developer, I want to run a single command (`ratels scan`) that
// scans my environment in general, so that I can get a full system
// snapshot and report on demand without tying it to a specific
// package install.
//
// Every other report in this tool brackets a package install: A4
// captures a "before" snapshot, runs the command, captures an "after"
// snapshot, and A9 diffs the pair. A standalone scan has no install
// to bracket, so it needs a different "before" to diff against.
//
// The approach here: diff against the most recently saved snapshot on
// disk (from any previous run — an install OR a scan). That turns
// SnapshotStore into a rolling baseline: "what changed since the last
// time I looked," not just "what changed during this one install."
// The very first scan on a machine has nothing to compare against, so
// it establishes a baseline instead of rendering a (meaningless,
// all-zero) diff against itself.

'use strict';

const { captureBeforeSnapshot } = require('./BeforeSnapshot');
const { computeStructuredDiff } = require('./StructuredDiffEngine');
const { renderPlainTextReport } = require('./PlainTextReport');
const { listSnapshots, loadSnapshot, saveSnapshot, saveReport } = require('./SnapshotStore');

/**
 * Builds a minimal "baseline established" report for the very first
 * scan on a machine, when there's no prior snapshot to diff against.
 * Shaped compatibly with computeStructuredDiff()'s output so
 * renderPlainTextReport() (and anything else downstream) can render
 * it without special-casing — the optional-chaining fallbacks already
 * in PlainTextReport.js handle the missing sections gracefully.
 */
function buildBaselineReport(current) {
  return {
    meta: {
      beforeId: null,
      afterId: current.id,
      beforeCapturedAt: null,
      afterCapturedAt: current.capturedAt,
      os: current.os,
      command: null,
      args: null,
    },
    envPathShell: undefined,
    networkProcessTemp: undefined,
    security: undefined,
    overallRisk: 'none',
    summary: [
      'First scan on this machine — baseline established, nothing to compare against yet.',
      'Run "ratels scan" again later to see what changed since this baseline.',
    ],
  };
}

/**
 * Runs a full standalone scan: captures the current system state,
 * diffs it against the most recently saved snapshot (if any), saves
 * the new snapshot and report, and returns everything a CLI or other
 * caller needs to display and act on.
 *
 * @returns {Promise<{
 *   isBaseline: boolean,
 *   previous: object|null,   // the prior snapshot diffed against, or null on first run
 *   current: object,         // the snapshot just captured
 *   report: object,          // from computeStructuredDiff() or buildBaselineReport()
 *   text: string,            // from renderPlainTextReport(report)
 *   snapshotPath: string,
 *   jsonPath: string,
 *   textPath: string,
 * }>}
 */
async function runFullScan() {
  const existing = listSnapshots(); // newest first
  const previous = existing.length > 0 ? loadSnapshot(existing[0].id) : null;

  const current = await captureBeforeSnapshot({ type: 'scan' });
  const snapshotPath = saveSnapshot(current);

  const isBaseline = previous === null;
  const report = isBaseline ? buildBaselineReport(current) : computeStructuredDiff(previous, current);
  const text = renderPlainTextReport(report);

  const { jsonPath, textPath } = saveReport(report, text);

  return { isBaseline, previous, current, report, text, snapshotPath, jsonPath, textPath };
}

module.exports = {
  runFullScan,
};

// Allow running this file directly for a quick manual check:
//   node core/FullScan.js
if (require.main === module) {
  runFullScan().then((result) => {
    if (result.isBaseline) {
      console.error('First scan — baseline established, no prior snapshot to compare against.');
    } else {
      console.error(`Comparing against previous snapshot: ${result.previous.id} (${result.previous.capturedAt})`);
    }
    console.error(`Saved snapshot: ${result.snapshotPath}`);
    console.error(`Saved report (json): ${result.jsonPath}`);
    console.error(`Saved report (text): ${result.textPath}`);
    console.log('\n' + result.text);
  });
}