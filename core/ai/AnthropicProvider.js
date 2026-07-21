// core/ai/AnthropicProvider.js
//
// User Story E3 (8 pts · Low)
// As a developer, I want to optionally use a cloud API provider
// (OpenAI or Anthropic) for AI analysis, so that I can get
// higher-quality analysis when I'm comfortable sending data
// off-device.
//
// This is the Anthropic half of E3. The API key comes from
// Config.js's getApiKey() (env-var placeholder or the encrypted
// CredentialStore, E4) — never handled or logged here directly.

'use strict';

const ANTHROPIC_VERSION = '2023-06-01';

/**
 * Sends a prompt to Anthropic's Messages API and returns the response
 * text.
 *
 * @param {string} prompt
 * @param {object} config - the ai.anthropic section of the config
 * @param {string} apiKey - resolved via Config.getApiKey('anthropic')
 * @returns {Promise<string>}
 */
async function analyze(prompt, config = {}, apiKey) {
  if (!apiKey) {
    throw new Error(
      'No Anthropic API key configured. Set the ANTHROPIC_API_KEY environment variable, or store one with: ' +
        'node core/CredentialStore.js set anthropic <your-key>'
    );
  }

  const model = config.model || 'claude-sonnet-5';

  let response;
  try {
    response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': ANTHROPIC_VERSION,
      },
      body: JSON.stringify({
        model,
        max_tokens: 1024,
        messages: [{ role: 'user', content: prompt }],
      }),
    });
  } catch (err) {
    throw new Error(`Could not reach Anthropic's API: ${err.message}`);
  }

  if (!response.ok) {
    const body = await response.text().catch(() => '');
    throw new Error(`Anthropic request failed (${response.status} ${response.statusText}): ${body.slice(0, 300)}`);
  }

  const data = await response.json();
  const text = (data?.content || [])
    .filter((block) => block.type === 'text')
    .map((block) => block.text)
    .join('\n')
    .trim();

  if (!text) {
    throw new Error('Anthropic returned no response text.');
  }
  return text;
}

module.exports = {
  analyze,
};