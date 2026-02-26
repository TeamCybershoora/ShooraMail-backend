import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import dotenv from 'dotenv';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const backendRoot = path.resolve(__dirname, '..', '..');

// Support running backend from either repository root or backend directory.
dotenv.config({ path: path.resolve(backendRoot, '.env') });
dotenv.config();

function asInt(value, fallback) {
  const parsed = Number.parseInt(String(value ?? ''), 10);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  return parsed;
}

function asBool(value, fallback = false) {
  if (value == null || value === '') {
    return fallback;
  }
  const normalized = String(value).trim().toLowerCase();
  return normalized === '1' || normalized === 'true' || normalized === 'yes';
}

function asList(value, fallback = []) {
  if (!value || !String(value).trim()) {
    return fallback;
  }
  return String(value)
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

function resolveTrustProxy(value, nodeEnv = 'development') {
  const raw = String(value ?? '').trim();
  if (!raw) {
    // Render/prod environments commonly run behind a reverse proxy.
    return String(nodeEnv).trim().toLowerCase() === 'production' ? 1 : false;
  }

  const normalized = raw.toLowerCase();
  if (normalized === 'true' || normalized === 'yes') {
    return true;
  }
  if (normalized === 'false' || normalized === 'no') {
    return false;
  }

  const parsed = Number.parseInt(raw, 10);
  if (Number.isFinite(parsed) && parsed >= 0) {
    return parsed;
  }

  // Express also accepts subnet strings/lists for trust proxy.
  return raw;
}

function normalizeSecret(value) {
  const trimmed = String(value ?? '').trim();
  if (!trimmed) {
    return '';
  }
  return trimmed.replace(/^["']|["']$/g, '');
}

function asFlexibleSecretList(value) {
  const raw = String(value ?? '').trim();
  if (!raw) {
    return [];
  }

  if (raw.startsWith('[') && raw.endsWith(']')) {
    try {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        return parsed
          .map((item) => normalizeSecret(item))
          .filter(Boolean);
      }
    } catch {
      // Fallback to delimiter parsing below.
    }
  }

  return raw
    .split(/[\n,;]+/)
    .map((item) => normalizeSecret(item))
    .filter(Boolean);
}

function readFallbackEncryptionKeys() {
  const names = [
    'ENCRYPTION_KEY_FALLBACKS',
    'ENCRYPTION_KEY_FALLBACK',
    'OLD_ENCRYPTION_KEYS',
    'OLD_ENCRYPTION_KEY',
  ];

  const out = [];
  const seen = new Set();
  for (const name of names) {
    const keys = asFlexibleSecretList(process.env[name]);
    for (const key of keys) {
      if (!key || seen.has(key)) {
        continue;
      }
      seen.add(key);
      out.push(key);
    }
  }
  return out;
}

function resolveSmtpSecureValue() {
  const configured =
    process.env.STACKMAIL_SMTP_SECURE ?? process.env.GMAIL_SMTP_SECURE;
  if (configured != null && String(configured).trim() !== '') {
    return asBool(configured, true);
  }

  const smtpPort = asInt(
    process.env.STACKMAIL_SMTP_PORT || process.env.GMAIL_SMTP_PORT,
    587,
  );
  return smtpPort === 465;
}

export const env = {
  nodeEnv: (process.env.NODE_ENV || 'development').trim(),
  port: asInt(process.env.PORT, 3000),
  trustProxy: resolveTrustProxy(
    process.env.TRUST_PROXY,
    process.env.NODE_ENV || 'development',
  ),
  logLevel: (process.env.LOG_LEVEL || 'info').trim().toLowerCase(),
  corsOrigins: asList(process.env.CORS_ORIGINS, ['*']),
  rateLimit: {
    windowMs: asInt(process.env.RATE_LIMIT_WINDOW_MS, 60_000),
    max: asInt(process.env.RATE_LIMIT_MAX, 120),
    authMax: asInt(process.env.RATE_LIMIT_AUTH_MAX, 30),
  },
  jwt: {
    secret: normalizeSecret(process.env.JWT_SECRET),
    issuer: (process.env.JWT_ISSUER || 'shoora-mail').trim(),
    audience: (process.env.JWT_AUDIENCE || 'shoora-mail-app').trim(),
    expiresIn: (process.env.JWT_EXPIRES_IN || '7d').trim(),
  },
  appAuth: {
    email: (process.env.APP_LOGIN_EMAIL || '').trim().toLowerCase(),
    password: process.env.APP_LOGIN_PASSWORD || '',
    passwordHash: (process.env.APP_LOGIN_PASSWORD_HASH || '').trim(),
  },
  stackmail: {
    directLoginEnabled: asBool(process.env.STACKMAIL_DIRECT_LOGIN_ENABLED, true),
  },
  storage: {
    filePath: (process.env.STORAGE_FILE_PATH || './backend/data/store.json').trim(),
  },
  encryption: {
    key: normalizeSecret(process.env.ENCRYPTION_KEY),
    fallbackKeys: readFallbackEncryptionKeys(),
  },
  google: {
    clientId: (process.env.GOOGLE_CLIENT_ID || '').trim(),
    clientSecret: (process.env.GOOGLE_CLIENT_SECRET || '').trim(),
    redirectUri: (process.env.GOOGLE_REDIRECT_URI || '').trim(),
    authBaseUrl: (process.env.GOOGLE_AUTH_BASE_URL || 'https://accounts.google.com/o/oauth2/v2/auth').trim(),
    tokenUrl: (process.env.GOOGLE_TOKEN_URL || 'https://oauth2.googleapis.com/token').trim(),
    oauthScopes: asList(process.env.GOOGLE_OAUTH_SCOPES, [
      'openid',
      'email',
      'profile',
      'https://mail.google.com/',
    ]),
  },
  gmail: {
    // Prefer STACKMAIL_* variables. GMAIL_* kept for backward compatibility.
    imapHost: (
      process.env.STACKMAIL_IMAP_HOST ||
      process.env.GMAIL_IMAP_HOST ||
      'imap.stackmail.com'
    ).trim(),
    imapPort: asInt(
      process.env.STACKMAIL_IMAP_PORT || process.env.GMAIL_IMAP_PORT,
      993,
    ),
    imapSecure: asBool(
      process.env.STACKMAIL_IMAP_SECURE || process.env.GMAIL_IMAP_SECURE,
      true,
    ),
    imapRejectUnauthorized: asBool(
      process.env.STACKMAIL_IMAP_REJECT_UNAUTHORIZED || process.env.GMAIL_IMAP_REJECT_UNAUTHORIZED,
      true,
    ),
    smtpHost: (
      process.env.STACKMAIL_SMTP_HOST ||
      process.env.GMAIL_SMTP_HOST ||
      'smtp.stackmail.com'
    ).trim(),
    smtpPort: asInt(
      process.env.STACKMAIL_SMTP_PORT || process.env.GMAIL_SMTP_PORT,
      587,
    ),
    smtpSecure: resolveSmtpSecureValue(),
  },
  fcm: {
    serviceAccountPath: (process.env.FCM_SERVICE_ACCOUNT_PATH || '').trim(),
    serviceAccountJson: (process.env.FCM_SERVICE_ACCOUNT_JSON || '').trim(),
    androidPriority: (process.env.FCM_ANDROID_PRIORITY || 'high').trim(),
    ttlSeconds: asInt(process.env.FCM_TTL_SECONDS, 3600),
  },
  smtpQueue: {
    maxAttempts: asInt(process.env.SMTP_QUEUE_MAX_ATTEMPTS, 4),
    workerIntervalMs: asInt(process.env.SMTP_QUEUE_WORKER_MS, 2500),
  },
  imapWatch: {
    maxReconnectDelayMs: asInt(process.env.IMAP_MAX_RECONNECT_MS, 60_000),
    baseReconnectDelayMs: asInt(process.env.IMAP_BASE_RECONNECT_MS, 2000),
    commandTimeoutMs: asInt(process.env.IMAP_COMMAND_TIMEOUT_MS, 15_000),
  },
};

export function assertEnv() {
  if (!env.jwt.secret || env.jwt.secret.length < 32) {
    throw new Error('JWT_SECRET must be set and at least 32 characters.');
  }

  if (!env.encryption.key || env.encryption.key.length < 32) {
    throw new Error('ENCRYPTION_KEY must be set and at least 32 characters.');
  }

  if (
    !env.stackmail.directLoginEnabled &&
    (!env.appAuth.email || (!env.appAuth.password && !env.appAuth.passwordHash))
  ) {
    throw new Error(
      'Set STACKMAIL_DIRECT_LOGIN_ENABLED=true or configure APP_LOGIN_EMAIL with APP_LOGIN_PASSWORD/APP_LOGIN_PASSWORD_HASH.',
    );
  }
}
