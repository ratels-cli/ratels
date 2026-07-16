// core/SnapshotStore.js
//
// User Story B3 (2 pts · High)
// As a developer, I want to save snapshots and reports locally for
// later review, so that I have an audit trail I can return to.
//
// Paths match the config shape sketched out in D1
// (paths.snapshotStore / paths.auditArchive) so this module can be
// pointed at custom locations once D1/D3 land; for now it uses the
// same sane defaults on its own.

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

const DEFAULT_PATHS = Object.freeze({
  snapshotStore: path.join(os.homedir(), '.pkg_monitor', 'snapshots'),
  auditArchive: path.join(os.homedir(), '.pkg_monitor', 'reports'),
});

/** Expands a leading `~` to the user's home directory, if present. */
function expandHome(p) {
  if (p.startsWith('~')) {
    return path.join(os.homedir(), p.slice(1));
  }
  return p;
}

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

/**
 * Saves a single snapshot (before or after) as JSON.
 *
 * @param {object} snapshot - from captureBeforeSnapshot()/captureAfterSnapshot()
 * @param {object} [options]
 * @param {string} [options.dir] - override the snapshot storage directory
 * @returns {string} the full path the snapshot was written to
 */
function saveSnapshot(snapshot, options = {}) {
  const dir = expandHome(options.dir || DEFAULT_PATHS.snapshotStore);
  ensureDir(dir);
  const filePath = path.join(dir, `${snapshot.id}.json`);
  fs.writeFileSync(filePath, JSON.stringify(snapshot, null, 2));
  return filePath;
}

/**
 * Saves a full before/after snapshot pair in one call.
 * @returns {{beforePath: string, afterPath: string}}
 */
function saveSnapshotPair(before, after, options = {}) {
  return {
    beforePath: saveSnapshot(before, options),
    afterPath: saveSnapshot(after, options),
  };
}

/**
 * Saves a structured diff report (from StructuredDiffEngine.js), both
 * as JSON (for tooling / B4's --json mode) and as plain text (from
 * B1's renderPlainTextReport), so the audit trail is readable without
 * re-running anything.
 *
 * @param {object} report - from computeStructuredDiff()
 * @param {string} plainText - from renderPlainTextReport(report)
 * @param {object} [options]
 * @param {string} [options.dir] - override the report storage directory
 * @returns {{jsonPath: string, textPath: string, id: string}}
 */
function saveReport(report, plainText, options = {}) {
  const dir = expandHome(options.dir || DEFAULT_PATHS.auditArchive);
  ensureDir(dir);

  const id = `report-${report?.meta?.afterId || Date.now()}`;
  const jsonPath = path.join(dir, `${id}.json`);
  const textPath = path.join(dir, `${id}.txt`);

  fs.writeFileSync(jsonPath, JSON.stringify(report, null, 2));
  fs.writeFileSync(textPath, plainText);

  return { jsonPath, textPath, id };
}

/**
 * Lists saved snapshots, newest first.
 * @returns {{id: string, path: string, mtime: string}[]}
 */
function listSnapshots(options = {}) {
  const dir = expandHome(options.dir || DEFAULT_PATHS.snapshotStore);
  return listJsonFiles(dir);
}

/**
 * Lists saved reports, newest first (JSON files only; each has a
 * matching .txt sibling with the same base name).
 * @returns {{id: string, path: string, mtime: string}[]}
 */
function listReports(options = {}) {
  const dir = expandHome(options.dir || DEFAULT_PATHS.auditArchive);
  return listJsonFiles(dir);
}

function listJsonFiles(dir) {
  try {
    return fs
      .readdirSync(dir)
      .filter((name) => name.endsWith('.json'))
      .map((name) => {
        const fullPath = path.join(dir, name);
        const stat = fs.statSync(fullPath);
        return { id: name.replace(/\.json$/, ''), path: fullPath, mtime: stat.mtime.toISOString() };
      })
      .sort((a, b) => b.mtime.localeCompare(a.mtime));
  } catch {
    return [];
  }
}

/** Loads a saved snapshot by id or filename. */
function loadSnapshot(idOrFilename, options = {}) {
  const dir = expandHome(options.dir || DEFAULT_PATHS.snapshotStore);
  const filePath = idOrFilename.endsWith('.json') ? path.join(dir, idOrFilename) : path.join(dir, `${idOrFilename}.json`);
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

/** Loads a saved report (JSON form) by id or filename. */
function loadReport(idOrFilename, options = {}) {
  const dir = expandHome(options.dir || DEFAULT_PATHS.auditArchive);
  const filePath = idOrFilename.endsWith('.json') ? path.join(dir, idOrFilename) : path.join(dir, `${idOrFilename}.json`);
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

module.exports = {
  DEFAULT_PATHS,
  saveSnapshot,
  saveSnapshotPair,
  saveReport,
  listSnapshots,
  listReports,
  loadSnapshot,
  loadReport,
};