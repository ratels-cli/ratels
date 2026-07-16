// core/EnvPathShellDiff.js
//
// User Story A6 (5 pts · High)
// As a developer, I want the tool to record changes to environment
// variables, PATH ordering, and shell configuration files, so that I
// can catch PATH hijacking or shell tampering.
//
// Consumes a pair of snapshots produced by BeforeSnapshot.js /
// AfterSnapshot.js (both now include `state.env`, `state.path`, and
// `state.shellConfigFiles`) and produces a focused diff covering just
// this story's three concerns. This feeds into A9's overall
// structured diff engine as one section of the full report.

'use strict';

/**
 * Diffs two flat env var objects.
 * @returns {{added: object, removed: object, changed: object}}
 */
function diffEnvVars(beforeEnv = {}, afterEnv = {}) {
  const added = {};
  const removed = {};
  const changed = {};

  for (const key of Object.keys(afterEnv)) {
    if (!(key in beforeEnv)) {
      added[key] = afterEnv[key];
    } else if (beforeEnv[key] !== afterEnv[key]) {
      changed[key] = { before: beforeEnv[key], after: afterEnv[key] };
    }
  }
  for (const key of Object.keys(beforeEnv)) {
    if (!(key in afterEnv)) {
      removed[key] = beforeEnv[key];
    }
  }

  return { added, removed, changed };
}

/**
 * Diffs PATH as an ORDERED list — this is deliberately order-sensitive,
 * since PATH hijacking often works by reordering rather than by adding
 * an entirely new entry (e.g. moving a writable directory ahead of
 * /usr/bin so a malicious `sudo` or `ls` shadows the real one).
 *
 * @returns {{
 *   before: string[], after: string[],
 *   added: string[], removed: string[],
 *   reordered: boolean,
 *   prependedEntries: string[]  // new entries inserted ahead of the first pre-existing entry — highest risk
 * }}
 */
function diffPath(beforePath = [], afterPath = []) {
  const beforeSet = new Set(beforePath);
  const afterSet = new Set(afterPath);

  const added = afterPath.filter((entry) => !beforeSet.has(entry));
  const removed = beforePath.filter((entry) => !afterSet.has(entry));

  const commonBefore = beforePath.filter((entry) => afterSet.has(entry));
  const commonAfter = afterPath.filter((entry) => beforeSet.has(entry));
  const reordered = commonBefore.join('\0') !== commonAfter.join('\0');

  const firstCommonIndex = afterPath.findIndex((entry) => beforeSet.has(entry));
  const prependedEntries = firstCommonIndex === -1 ? added : afterPath.slice(0, firstCommonIndex);

  return { before: beforePath, after: afterPath, added, removed, reordered, prependedEntries };
}

/**
 * Diffs shell configuration file contents between two snapshots.
 * Flags: files that appeared, disappeared, or changed content — plus
 * a quick heuristic flag for lines that touch PATH or add an alias/
 * function, which are the most common tampering vectors.
 *
 * @returns {{
 *   added: string[],    // file paths that now exist but didn't before
 *   removed: string[],  // file paths that existed before but not now
 *   changed: Array<{path: string, addedLines: string[], removedLines: string[], suspicious: boolean}>
 * }}
 */
function diffShellConfigFiles(beforeFiles = {}, afterFiles = {}) {
  const added = [];
  const removed = [];
  const changed = [];

  const suspiciousPattern = /\b(PATH|alias|function|export)\b/i;

  for (const filePath of Object.keys(afterFiles)) {
    if (!(filePath in beforeFiles)) {
      added.push(filePath);
      continue;
    }
    const beforeContent = beforeFiles[filePath].content;
    const afterContent = afterFiles[filePath].content;
    if (beforeContent === afterContent) continue;

    const beforeLines = new Set(beforeContent.split('\n'));
    const afterLines = new Set(afterContent.split('\n'));
    const addedLines = [...afterLines].filter((line) => !beforeLines.has(line) && line.trim() !== '');
    const removedLines = [...beforeLines].filter((line) => !afterLines.has(line) && line.trim() !== '');
    const suspicious = [...addedLines, ...removedLines].some((line) => suspiciousPattern.test(line));

    changed.push({ path: filePath, addedLines, removedLines, suspicious });
  }

  for (const filePath of Object.keys(beforeFiles)) {
    if (!(filePath in afterFiles)) {
      removed.push(filePath);
    }
  }

  return { added, removed, changed };
}

/**
 * Runs the full A6 diff (env vars + PATH + shell config files) against
 * a before/after snapshot pair from BeforeSnapshot.js / AfterSnapshot.js.
 *
 * @param {object} before - snapshot from captureBeforeSnapshot()
 * @param {object} after - snapshot from captureAfterSnapshot()
 * @returns {{
 *   env: ReturnType<diffEnvVars>,
 *   path: ReturnType<diffPath>,
 *   shellConfigFiles: ReturnType<diffShellConfigFiles>,
 *   customFiles: ReturnType<diffShellConfigFiles>,
 *   hasSuspiciousChanges: boolean
 * }}
 */
function diffEnvPathShell(before, after) {
  const env = diffEnvVars(before?.state?.env, after?.state?.env);
  const path = diffPath(before?.state?.path, after?.state?.path);
  const shellConfigFiles = diffShellConfigFiles(before?.state?.shellConfigFiles, after?.state?.shellConfigFiles);
  // Reuses the same generic { path: {content, size, mtime} } diff
  // logic as shellConfigFiles — user-specified files from
  // config.customFiles are collected in exactly the same shape.
  const customFiles = diffShellConfigFiles(before?.state?.customFiles, after?.state?.customFiles);

  const hasSuspiciousChanges =
    path.prependedEntries.length > 0 ||
    path.reordered ||
    shellConfigFiles.changed.some((f) => f.suspicious) ||
    shellConfigFiles.added.length > 0 ||
    // Any change at all to a custom file counts as suspicious — the
    // user explicitly asked to be watching it, so there's no
    // "harmless" change to filter out here the way there is for
    // arbitrary shell config lines.
    customFiles.added.length > 0 ||
    customFiles.removed.length > 0 ||
    customFiles.changed.length > 0;

  return { env, path, shellConfigFiles, customFiles, hasSuspiciousChanges };
}

module.exports = {
  diffEnvVars,
  diffPath,
  diffShellConfigFiles,
  diffEnvPathShell,
};

// Allow running this file directly against two saved snapshot JSON files:
//   node core/EnvPathShellDiff.js before.json after.json
if (require.main === module) {
  const fs = require('fs');
  const [beforePath, afterPath] = process.argv.slice(2);

  if (!beforePath || !afterPath) {
    console.error('Usage: node core/EnvPathShellDiff.js <before.json> <after.json>');
    process.exit(1);
  }

  const before = JSON.parse(fs.readFileSync(beforePath, 'utf8'));
  const after = JSON.parse(fs.readFileSync(afterPath, 'utf8'));

  console.log(JSON.stringify(diffEnvPathShell(before, after), null, 2));
}