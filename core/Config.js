// core/Config.js
//
// User Story D1 (5 pts · High)
// As a developer, I want to be able to open the config file and see
// settings for AI provider selection, credentials, save paths, and
// per-collector on/off toggles, so that I can control the tool's
// behavior without editing source code.
//
// Config file lives at ~/.pkgmonitorrc (YAML), matching the example
// in the Product Backlog doc (Section 1, Epic D). Requires the
// `js-yaml` package:
//   npm install js-yaml
//
// Note on credentials: this module resolves ${ENV_VAR}-style
// placeholders in the ai.<provider>.apiKey fields (handy for CI, where
// the env var itself is already the secure store), but does NOT
// accept or persist a literal plaintext key typed into this file.
// Persistent, on-disk credential storage is E4's job — see
// CredentialStore.js — and getApiKey() below checks both, env-var
// placeholder first, then the encrypted store.

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const yaml = require('js-yaml');

const CONFIG_PATH = path.join(os.homedir(), '.pkgmonitorrc');

/**
 * Default configuration, matching the example .pkgmonitorrc shape
 * from the Product Backlog doc (Section 1, Epic D / D1).
 */
const DEFAULT_CONFIG = Object.freeze({
  ai: {
    provider: 'ollama', // ollama | openai | anthropic
    ollama: {
      endpoint: 'http://localhost:11434',
      model: 'llama3',
    },
    openai: {
      apiKey: '${OPENAI_API_KEY}',
      model: 'gpt-4o',
    },
    anthropic: {
      apiKey: '${ANTHROPIC_API_KEY}',
      model: 'claude-sonnet-5',
    },
  },
  paths: {
    auditArchive: '~/.pkg_monitor/reports',
    snapshotStore: '~/.pkg_monitor/snapshots',
  },
  collectors: {
    sshKeys: true,
    sudoers: true,
    launchAgents: true,
    network: true,
    npmAudit: false,
  },
  // Which shell/profile config files to scan for tampering (A6),
  // broken out per OS since each shell ecosystem uses different files.
  // Paths are relative to the user's home directory unless they start
  // with '/' or a drive letter. Edit these lists to add a shell you
  // use that isn't covered, or remove ones you don't use.
  shellConfigFiles: {
    macos: ['.bashrc', '.bash_profile', '.bash_login', '.profile', '.zshrc', '.zprofile', '.zshenv', '.config/fish/config.fish'],
    linux: ['.bashrc', '.bash_profile', '.bash_login', '.profile', '.zshrc', '.zprofile', '.zshenv', '.config/fish/config.fish'],
    windows: [
      'Documents\\WindowsPowerShell\\Microsoft.PowerShell_profile.ps1',
      'Documents\\PowerShell\\Microsoft.PowerShell_profile.ps1',
    ],
    // System-wide files (not per-user) — PATH hijacking doesn't have
    // to happen in your personal profile.
    systemWide: {
      macos: ['/etc/profile', '/etc/bashrc', '/etc/zshrc'],
      linux: ['/etc/profile', '/etc/bash.bashrc', '/etc/zsh/zshrc'],
      windows: [],
    },
  },
  notifications: {
    enabled: false,
    channel: 'slack',
    webhookUrl: '',
  },
});

/** Deep-merges `override` onto `base`, without mutating either. */
function deepMerge(base, override) {
  if (typeof base !== 'object' || base === null) return override ?? base;
  if (typeof override !== 'object' || override === null) return override ?? base;

  const result = { ...base };
  for (const key of Object.keys(override)) {
    result[key] = deepMerge(base[key], override[key]);
  }
  return result;
}

/** Returns the path to the active config file (for a future `config path` command, D2). */
function getConfigPath() {
  return CONFIG_PATH;
}

/**
 * Writes the default config file if one doesn't already exist yet.
 * Safe to call on every startup — never overwrites an existing file.
 * @returns {boolean} true if a new file was created
 */
function ensureConfigExists() {
  if (fs.existsSync(CONFIG_PATH)) return false;
  const header =
    '# Supply Chain Security Monitor configuration\n' +
    '# See docs for all available options.\n\n';
  fs.writeFileSync(CONFIG_PATH, header + yaml.dump(DEFAULT_CONFIG), { mode: 0o600 });
  return true;
}

/**
 * Loads the config file, merged over the defaults so a partial file
 * (e.g. just overriding `collectors.npmAudit`) still works. Missing
 * file is treated as "use all defaults" rather than an error.
 *
 * @returns {object} the merged config
 */
function loadConfig() {
  if (!fs.existsSync(CONFIG_PATH)) {
    return JSON.parse(JSON.stringify(DEFAULT_CONFIG));
  }

  const raw = fs.readFileSync(CONFIG_PATH, 'utf8');
  let parsed;
  try {
    parsed = yaml.load(raw) || {};
  } catch (err) {
    throw new Error(`Failed to parse config file at ${CONFIG_PATH}: ${err.message}`);
  }

  return deepMerge(DEFAULT_CONFIG, parsed);
}

/** Writes a full config object back to disk as YAML. */
function saveConfig(config) {
  const header =
    '# Supply Chain Security Monitor configuration\n' +
    '# See docs for all available options.\n\n';
  fs.writeFileSync(CONFIG_PATH, header + yaml.dump(config), { mode: 0o600 });
}

/** Resolves a single `${ENV_VAR}` placeholder string, or returns it unchanged if it isn't one. */
function resolveEnvPlaceholder(value) {
  if (typeof value !== 'string') return value;
  const match = value.match(/^\$\{([A-Z0-9_]+)\}$/i);
  if (!match) return value;
  return process.env[match[1]] || '';
}

/**
 * Resolves the API key for a given AI provider. Checks, in order:
 *   1. `${ENV_VAR}` placeholder in the config file, if it resolves to
 *      a non-empty value (useful in CI, where the secret is already
 *      injected as an env var and never touches disk at all).
 *   2. The encrypted local credential store (E4's CredentialStore.js).
 * Returns null if neither has a value — never throws, since "no key
 * configured yet" is a normal state (e.g. provider: ollama).
 *
 * @param {'openai'|'anthropic'} provider
 * @param {object} [config] - defaults to loadConfig()
 * @returns {string|null}
 */
function getApiKey(provider, config = loadConfig()) {
  const fromConfig = resolveEnvPlaceholder(config?.ai?.[provider]?.apiKey);
  if (fromConfig) return fromConfig;

  // Lazily required to avoid a hard dependency cycle / cost when unused.
  const { getCredential } = require('./CredentialStore');
  return getCredential(provider);
}

/** Convenience: is a given collector enabled per the config? */
function isCollectorEnabled(name, config = loadConfig()) {
  return Boolean(config?.collectors?.[name]);
}

module.exports = {
  CONFIG_PATH,
  DEFAULT_CONFIG,
  getConfigPath,
  ensureConfigExists,
  loadConfig,
  saveConfig,
  getApiKey,
  isCollectorEnabled,
};

// Allow running this file directly for a quick manual check:
//   node core/Config.js
if (require.main === module) {
  const created = ensureConfigExists();
  if (created) console.error(`Created default config at ${CONFIG_PATH}`);
  console.log(JSON.stringify(loadConfig(), null, 2));
}