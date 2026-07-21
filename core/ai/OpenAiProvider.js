// core/ai/OpenAiProvider.js
//
// User Story E3 (8 pts · Low)
// As a developer, I want to optionally use a cloud API provider
// (OpenAI or Anthropic) for AI analysis, so that I can get
// higher-quality analysis when I'm comfortable sending data
// off-device.
//
// This is the OpenAI half of E3. The API key comes from Config.js's
// getApiKey() (env-var placeholder or the encrypted CredentialStore,
// E4) — never handled or logged here directly.

'use strict';

/**
 * Sends a prompt to OpenAI's chat completions API and returns the
 * response text.
 *
 * @param {string} prompt
 * @param {object} config - the ai.openai section of the config
 * @param {string} apiKey - resolved via Config.getApiKey('openai')
 * @returns {Promise<string>}
 */
async function analyze(prompt, config = {}, apiKey) {
  if (!apiKey) {
    throw new Error(
      'No OpenAI API key configured. Set the OPENAI_API_KEY environment variable, or store one with: ' +
        'node core/CredentialStore.js set openai <your-key>'
    );
  }

  const model = config.model || 'gpt-4o';

  let response;
  try {
    response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model,
        messages: [{ role: 'user', content: prompt }],
        temperature: 0.2,
      }),
    });
  } catch (err) {
    throw new Error(`Could not reach OpenAI's API: ${err.message}`);
  }

  if (!response.ok) {
    const body = await response.text().catch(() => '');
    throw new Error(`OpenAI request failed (${response.status} ${response.statusText}): ${body.slice(0, 300)}`);
  }

  const data = await response.json();
  const text = data?.choices?.[0]?.message?.content;
  if (!text) {
    throw new Error('OpenAI returned no response text.');
  }
  return text.trim();
}

module.exports = {
  analyze,
};