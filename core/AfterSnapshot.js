// core/AfterSnapshot.js
//
// User Story A5 (5 pts · High)
// As a developer, I want to capture an "after" snapshot once
// installation completes, so that I can see exactly what changed.
//
// Reuses the exact same collectors as BeforeSnapshot.js (A3) so the
// two snapshots are directly comparable — same shape, same collection
// method, just a different point in time and type: 'after'. That
// consistency is what makes A9's diff engine meaningful.

'use strict';

const { detectOs } = require('./OsDetection');
const { detectPackageManagers } = require('./PackageManagerDetection');
const {
  collectEnvVars,
  collectPath,
  collectShellConfigFiles,
  collectProcesses,
  collectNetworkPorts,
  collectTempFiles,
  collectSecurityState,
} = require('./BeforeSnapshot');

/**
 * Captures a full "after" snapshot of the system, once installation
 * has completed.
 *
 * @param {object} [options]
 * @param {string} [options.beforeId] - id of the matching "before" snapshot,
 *   so the pair can be linked before being handed to the diff engine (A9).
 * @returns {Promise<object>} snapshot - same shape as BeforeSnapshot's,
 *   but type: 'after' and (if provided) a `beforeId` back-reference.
 */
async function captureAfterSnapshot(options = {}) {
  const osInfo = detectOs();

  const [packageManagers, processes, network] = await Promise.all([
    detectPackageManagers({ osId: osInfo.id }),
    collectProcesses(osInfo.id),
    collectNetworkPorts(osInfo.id),
  ]);

  return {
    id: `after-${Date.now()}`,
    type: 'after',
    beforeId: options.beforeId || null,
    capturedAt: new Date().toISOString(),
    os: osInfo,
    packageManagers,
    state: {
      env: collectEnvVars(),
      path: collectPath(),
      shellConfigFiles: collectShellConfigFiles(osInfo.id),
      processes,
      network,
      tempFiles: collectTempFiles(),
      security: collectSecurityState(osInfo.id),
    },
  };
}

module.exports = {
  captureAfterSnapshot,
};

// Allow running this file directly for a quick manual check:
//   node core/AfterSnapshot.js
if (require.main === module) {
  captureAfterSnapshot().then((snapshot) => {
    console.log(JSON.stringify(snapshot, null, 2));
  });
}