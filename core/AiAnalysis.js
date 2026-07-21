// core/AiAnalysis.js
//
// User Story E1 (8 pts · Medium)
// As a developer, I want to enable an optional AI-assisted analysis
// mode that reviews the diff and flags suspicious changes with a
// summary, so that I get a plain-language read on risk without
// manually interpreting every line.
//
// This is opt-in (never runs unless explicitly requested — see
// cli.js's --ai flag) and dispatches to whichever provider is
// configured in ai.provider: 'ollama' (E2, local, full detail) or
// 'openai'/'anthropic' (E3, cloud, redacted by default).
//
// PRIVACY NOTE: the structured diff report can contain genuinely
// sensitive material — actual env var values, real lines added to
// shell configs or custom watched files (which might be a .env file
// full of secrets), and SSH-related detail. For the local Ollama
// provider that's fine, since nothing leaves the machine. For cloud
// providers, this module strips those values down to metadata
// (counts, paths, categories, severities) by default, and only
// includes the actual content if the caller explicitly opts in via
// `includeFullDetail: true` — matching E3's framing that sending data
// off-device should be a conscious choice, not an accidental default.

'use strict';

const ollamaProvider = require('./ai/OllamaProvider');
const openAiProvider = require('./ai/OpenAiProvider');
const anthropicProvider = require('./ai/AnthropicProvider');

/**
 * Produces a redacted, cloud-safe version of the report: keeps every
 * structural fact (what changed, where, how severe) but strips actual
 * secret-shaped content (env values, file line contents).
 */
function redactForCloud(report) {
  const redactLines = (lines) => (lines || []).map(() => '[redacted]');

  const security = report.security
    ? {
        ...report.security,
        findings: (report.security.findings || []).map((f) => ({
          severity: f.severity,
          category: f.category,
          message: f.message,
          // Drop f.detail (actual authorized_keys lines) — keep just the count.
          detailCount: f.detail ? f.detail.length : 0,
        })),
      }
    : report.security;

  const redactFileList = (fileDiff) =>
    fileDiff && {
      added: fileDiff.added,
      removed: fileDiff.removed,
      changed: (fileDiff.changed || []).map((f) => ({
        path: f.path,
        suspicious: f.suspicious,
        addedLineCount: (f.addedLines || []).length,
        removedLineCount: (f.removedLines || []).length,
        // Actual content redacted for cloud providers.
        addedLines: redactLines(f.addedLines),
        removedLines: redactLines(f.removedLines),
      })),
    };

  const envPathShell = report.envPathShell
    ? {
        env: {
          addedCount: Object.keys(report.envPathShell.env?.added || {}).length,
          removedCount: Object.keys(report.envPathShell.env?.removed || {}).length,
          changedCount: Object.keys(report.envPathShell.env?.changed || {}).length,
          // Keys only, never values — a value could be a secret.
          addedKeys: Object.keys(report.envPathShell.env?.added || {}),
          removedKeys: Object.keys(report.envPathShell.env?.removed || {}),
          changedKeys: Object.keys(report.envPathShell.env?.changed || {}),
        },
        path: {
          reordered: report.envPathShell.path?.reordered,
          added: report.envPathShell.path?.added,
          removed: report.envPathShell.path?.removed,
          prependedEntries: report.envPathShell.path?.prependedEntries,
        },
        shellConfigFiles: redactFileList(report.envPathShell.shellConfigFiles),
        customFiles: redactFileList(report.envPathShell.customFiles),
        hasSuspiciousChanges: report.envPathShell.hasSuspiciousChanges,
      }
    : report.envPathShell;

  return {
    meta: report.meta,
    envPathShell,
    networkProcessTemp: report.networkProcessTemp, // no secret-shaped values in here
    security,
    overallRisk: report.overallRisk,
    summary: report.summary,
  };
}

/** Builds the actual prompt text sent to the model. */
function buildPrompt(reportForPrompt) {
  return [
    'You are a security analyst reviewing a structured diff of system changes captured before and after a package installation (or a standalone system scan).',
    'Review the JSON below and produce:',
    '1. A short plain-language summary (2-4 sentences) of what happened, written for a developer who has not read the raw diff.',
    '2. A verdict: is this install/scan result safe to trust, worth a second look, or clearly dangerous — and why, in one or two sentences.',
    '3. If there are specific findings worth calling out by name (e.g. a specific file, port, or process), mention them explicitly.',
    '',
    'Be concise and direct. Do not restate the raw JSON back at me. Do not pad your answer with disclaimers.',
    '',
    'Structured diff:',
    JSON.stringify(reportForPrompt, null, 2),
  ].join('\n');
}

/**
 * Runs AI-assisted analysis on a structured diff report (from
 * computeStructuredDiff() or FullScan.js), using whichever provider
 * is configured.
 *
 * @param {object} report - from computeStructuredDiff()
 * @param {object} [options]
 * @param {object} [options.config] - defaults to Config.loadConfig()
 * @param {boolean} [options.includeFullDetail] - send unredacted content
 *   to a cloud provider. Ignored for Ollama, which always gets full
 *   detail since it never leaves the machine. Defaults to false.
 * @returns {Promise<{
 *   provider: string,
 *   model: string,
 *   text: string,
 *   redacted: boolean,
 * }>}
 */
async function runAiAnalysis(report, options = {}) {
  // Lazily required to avoid a hard dependency cycle with Config.js.
  const { loadConfig, getApiKey } = require('./Config');
  const config = options.config || loadConfig();
  const provider = config?.ai?.provider || 'ollama';

  const isCloud = provider === 'openai' || provider === 'anthropic';
  const redacted = isCloud && !options.includeFullDetail;
  const reportForPrompt = redacted ? redactForCloud(report) : report;
  const prompt = buildPrompt(reportForPrompt);

  let text;
  let model;

  if (provider === 'ollama') {
    model = config.ai.ollama?.model || 'llama3';
    text = await ollamaProvider.analyze(prompt, config.ai.ollama);
  } else if (provider === 'openai') {
    model = config.ai.openai?.model || 'gpt-4o';
    const apiKey = getApiKey('openai', config);
    text = await openAiProvider.analyze(prompt, config.ai.openai, apiKey);
  } else if (provider === 'anthropic') {
    model = config.ai.anthropic?.model || 'claude-sonnet-5';
    const apiKey = getApiKey('anthropic', config);
    text = await anthropicProvider.analyze(prompt, config.ai.anthropic, apiKey);
  } else {
    throw new Error(`Unknown AI provider "${provider}" — expected 'ollama', 'openai', or 'anthropic'. Check ai.provider in ~/.ratelsrc.`);
  }

  return { provider, model, text, redacted };
}

module.exports = {
  runAiAnalysis,
  redactForCloud,
  buildPrompt,
};

// Allow running this file directly against a saved structured-diff
// report JSON (from StructuredDiffEngine.js or FullScan.js):
//   node core/AiAnalysis.js report.json
if (require.main === module) {
  const fs = require('fs');
  const [reportPath] = process.argv.slice(2);

  if (!reportPath) {
    console.error('Usage: node core/AiAnalysis.js <report.json>');
    process.exit(1);
  }

  const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
  runAiAnalysis(report)
    .then((result) => {
      console.error(`Provider: ${result.provider} (${result.model})  |  redacted: ${result.redacted}\n`);
      console.log(result.text);
    })
    .catch((err) => {
      console.error(`AI analysis failed: ${err.message}`);
      process.exit(1);
    });
}