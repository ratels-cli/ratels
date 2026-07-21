// core/CredentialStore.js
//
// User Story E4 (5 pts · High)
// As a developer, I want my AI provider API keys stored securely
// (encrypted, never in plain snapshot files), so that sharing my
// snapshots or reports doesn't leak my credentials.
//
// API keys are NEVER written into snapshots or reports in the first
// place (BeforeSnapshot.js/AfterSnapshot.js don't touch this store at
// all), and if a developer chooses to persist a key locally rather
// than use an env var, it's encrypted at rest here with AES-256-GCM.
// The encryption key itself lives in a separate 0600 file, so a
// leaked credentials file alone is not enough to decrypt anything.

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const STORE_DIR = path.join(os.homedir(), '.ratels');
const KEY_FILE = path.join(STORE_DIR, 'credentials.key');
const CREDENTIALS_FILE = path.join(STORE_DIR, 'credentials.enc.json');
const LEGACY_STORE_DIR = path.join(os.homedir(), '.pkg_monitor');
const LEGACY_KEY_FILE = path.join(LEGACY_STORE_DIR, 'credentials.key');
const LEGACY_CREDENTIALS_FILE = path.join(LEGACY_STORE_DIR, 'credentials.enc.json');

const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH_BYTES = 32; // 256 bits
const IV_LENGTH_BYTES = 12; // recommended for GCM

function ensureStoreDir() {
  fs.mkdirSync(STORE_DIR, { recursive: true });
}

/**
 * Gets the local encryption key, generating and persisting a new
 * random one on first use. The key file is created with 0600
 * permissions (owner read/write only) and is never derived from the
 * API key or any guessable value.
 */
function getOrCreateEncryptionKey() {
  ensureStoreDir();

  if (fs.existsSync(KEY_FILE)) {
    return Buffer.from(fs.readFileSync(KEY_FILE, 'utf8').trim(), 'base64');
  }

  if (fs.existsSync(LEGACY_KEY_FILE)) {
    fs.renameSync(LEGACY_KEY_FILE, KEY_FILE);
    return Buffer.from(fs.readFileSync(KEY_FILE, 'utf8').trim(), 'base64');
  }

  const key = crypto.randomBytes(KEY_LENGTH_BYTES);
  fs.writeFileSync(KEY_FILE, key.toString('base64'), { mode: 0o600 });
  return key;
}

/** Encrypts a plaintext string, returning everything needed to decrypt it later. */
function encrypt(plaintext, key) {
  const iv = crypto.randomBytes(IV_LENGTH_BYTES);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
  };
}

/** Decrypts an entry produced by encrypt(). Throws if the key or data was tampered with. */
function decrypt(entry, key) {
  const decipher = crypto.createDecipheriv(ALGORITHM, key, Buffer.from(entry.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(entry.authTag, 'base64'));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(entry.ciphertext, 'base64')),
    decipher.final(),
  ]);
  return plaintext.toString('utf8');
}

function readCredentialsFile() {
  if (!fs.existsSync(CREDENTIALS_FILE)) {
    if (fs.existsSync(LEGACY_CREDENTIALS_FILE)) {
      ensureStoreDir();
      fs.renameSync(LEGACY_CREDENTIALS_FILE, CREDENTIALS_FILE);
    } else {
      return {};
    }
  }
  try {
    return JSON.parse(fs.readFileSync(CREDENTIALS_FILE, 'utf8'));
  } catch {
    return {};
  }
}

function writeCredentialsFile(data) {
  ensureStoreDir();
  fs.writeFileSync(CREDENTIALS_FILE, JSON.stringify(data, null, 2), { mode: 0o600 });
}

/**
 * Encrypts and persists an API key for a given provider.
 * @param {string} provider - e.g. 'openai', 'anthropic'
 * @param {string} apiKey - the plaintext key; never stored as-is
 */
function setCredential(provider, apiKey) {
  const key = getOrCreateEncryptionKey();
  const data = readCredentialsFile();
  data[provider] = encrypt(apiKey, key);
  writeCredentialsFile(data);
}

/**
 * Retrieves and decrypts the stored API key for a provider.
 * @returns {string|null} the plaintext key, or null if none is stored
 */
function getCredential(provider) {
  const data = readCredentialsFile();
  const entry = data[provider];
  if (!entry) return null;

  const key = getOrCreateEncryptionKey();
  try {
    return decrypt(entry, key);
  } catch {
    // Corrupted entry or key file mismatch — treat as "no credential"
    // rather than crashing the caller.
    return null;
  }
}

/** Removes a stored credential for a provider, if any. */
function deleteCredential(provider) {
  const data = readCredentialsFile();
  if (!(provider in data)) return false;
  delete data[provider];
  writeCredentialsFile(data);
  return true;
}

/**
 * Lists which providers currently have a stored credential — names
 * only, never the decrypted values, so this is safe to print or log.
 */
function listStoredProviders() {
  return Object.keys(readCredentialsFile());
}

module.exports = {
  setCredential,
  getCredential,
  deleteCredential,
  listStoredProviders,
};

// Allow running this file directly as a tiny credential-management CLI:
//   node core/CredentialStore.js set anthropic sk-ant-xxxxx
//   node core/CredentialStore.js get anthropic
//   node core/CredentialStore.js delete anthropic
//   node core/CredentialStore.js list
if (require.main === module) {
  const [action, provider, value] = process.argv.slice(2);

  if (action === 'set' && provider && value) {
    setCredential(provider, value);
    console.log(`Stored encrypted credential for "${provider}".`);
  } else if (action === 'get' && provider) {
    const value = getCredential(provider);
    console.log(value === null ? `No credential stored for "${provider}".` : value);
  } else if (action === 'delete' && provider) {
    const deleted = deleteCredential(provider);
    console.log(deleted ? `Deleted credential for "${provider}".` : `No credential stored for "${provider}".`);
  } else if (action === 'list') {
    const providers = listStoredProviders();
    console.log(providers.length ? providers.join('\n') : '(no credentials stored)');
  } else {
    console.error('Usage:');
    console.error('  node core/CredentialStore.js set <provider> <apiKey>');
    console.error('  node core/CredentialStore.js get <provider>');
    console.error('  node core/CredentialStore.js delete <provider>');
    console.error('  node core/CredentialStore.js list');
    process.exit(1);
  }
}