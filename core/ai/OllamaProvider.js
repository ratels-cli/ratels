// core/ai/OllamaProvider.js
//
// User Story E2 (5 pts · Medium)
// As a developer, I want to point the AI analysis at a local Ollama
// model, so that I can use AI-assisted review without sending my
// system data to a cloud provider.
//
// Talks to a local Ollama server over plain HTTP (default
// http://localhost:11434). Since the model runs on the same machine,
// this is the only provider that gets the FULL, unredacted diff
// detail by default — nothing here ever leaves the box.

'use strict';

/**
 * Sends a prompt to a local Ollama model and returns its response text.
 *
 * @param {string} prompt
 * @param {object} config - the ai.ollama section of the config
 * @returns {Promise<string>}
 */
async function analyze(prompt, config = {}) {
  const endpoint = config.endpoint || 'http://localhost:11434';
  const model = config.model || 'qwen3.5:9b-mlx';
  const url = `${endpoint.replace(/\/$/, '')}/api/generate`;

  let response;
  try {
    response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model, prompt, stream: false }),
    });
  } catch (err) {
    throw new Error(
      `Could not reach Ollama at ${endpoint} — is it running? (\`ollama serve\`, and \`ollama pull ${model}\` if you haven't yet). Original error: ${err.message}`
    );
  }

  if (!response.ok) {
    const body = await response.text().catch(() => '');
    throw new Error(`Ollama request failed (${response.status} ${response.statusText}): ${body.slice(0, 300)}`);
  }

  const data = await response.json();
  if (!data.response) {
    throw new Error('Ollama returned no response text — check the model name is correct and pulled locally.');
  }
  return data.response.trim();
}

module.exports = {
  analyze,
};