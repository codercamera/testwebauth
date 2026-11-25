import { Hono } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import type {
  AuthenticationResponseJSON,
  Base64URLString,
  RegistrationResponseJSON,
} from '@simplewebauthn/server';

type Bindings = {
  DB?: D1Database;
  ASSETS: Fetcher;
  SETUP_KEY?: string;
};

type Variables = {
  user: UserRow;
};

type UserRow = {
  id: string;
  email: string;
  display_name: string;
  role: string;
  password_hash: string | null;
  created_at: string;
};

type CredentialRow = {
  id: string;
  user_id: string;
  credential_id: string;
  public_key: string;
  counter: number;
  transports: string | null;
  device_type: string | null;
  backed_up: number;
  name: string;
  created_at: string;
  last_used_at: string | null;
};

type AppConfig = {
  appName: string;
  rpId: string;
  origin: string;
  installationComplete: boolean;
  passwordEnabled: boolean;
};

const app = new Hono<{ Bindings: Bindings; Variables: Variables }>();
const SESSION_COOKIE = 'passkey_lab_session';
const SCHEMA_VERSION = '1';
const CHALLENGE_TTL_MINUTES = 5;
const SESSION_TTL_DAYS = 7;

const schemaStatements = [
  `CREATE TABLE IF NOT EXISTS app_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`,
  `CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    password_hash TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`,
  `CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    credential_id TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    counter INTEGER NOT NULL DEFAULT 0,
    transports TEXT,
    device_type TEXT,
    backed_up INTEGER NOT NULL DEFAULT 0,
    name TEXT NOT NULL DEFAULT 'Passkey',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )`,
  `CREATE INDEX IF NOT EXISTS idx_credentials_user ON webauthn_credentials(user_id)`,
  `CREATE TABLE IF NOT EXISTS webauthn_challenges (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    challenge TEXT NOT NULL,
    purpose TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )`,
  `CREATE INDEX IF NOT EXISTS idx_challenges_expiry ON webauthn_challenges(expires_at)`,
  `CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )`,
  `CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token_hash)`,
  `CREATE TABLE IF NOT EXISTS authentication_events (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    event_type TEXT NOT NULL,
    success INTEGER NOT NULL,
    detail TEXT,
    ip_address TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
  )`,
];

app.use('/api/*', async (c, next) => {
  if (!['GET', 'HEAD', 'OPTIONS'].includes(c.req.method)) {
    const origin = c.req.header('Origin');
    if (origin && origin !== new URL(c.req.url).origin) {
      return c.json({ error: 'Cross-origin requests are not allowed.' }, 403);
    }
  }
  await next();
});

app.use('/api/auth/*', async (c, next) => {
  const publicRoutes = [
    '/api/auth/login/password',
    '/api/auth/login/passkey/options',
    '/api/auth/login/passkey/verify',
  ];
  if (publicRoutes.includes(c.req.path)) return next();

  const db = requireDatabase(c.env.DB);
  const user = await authenticatedUser(c, db);
  if (!user) return c.json({ error: 'Authentication required.' }, 401);
  c.set('user', user);
  await next();
});

app.get('/api/health', (c) => c.json({ ok: true }));

app.get('/api/setup/status', async (c) => {
  if (!c.env.DB) {
    return c.json({
      state: 'missing_database',
      setupKeyConfigured: Boolean(c.env.SETUP_KEY),
      message: 'The D1 binding named DB is not configured.',
    });
  }

  const exists = await tableExists(c.env.DB, 'app_meta');
  if (!exists) {
    return c.json({ state: 'empty', setupKeyConfigured: Boolean(c.env.SETUP_KEY) });
  }

  const config = await readConfig(c.env.DB);
  const admin = await c.env.DB.prepare(
    `SELECT id, email, display_name FROM users WHERE role = 'admin' ORDER BY created_at LIMIT 1`,
  ).first<{ id: string; email: string; display_name: string }>();

  return c.json({
    state: config.installationComplete ? 'ready' : 'awaiting_passkey',
    setupKeyConfigured: Boolean(c.env.SETUP_KEY),
    config,
    admin: admin ?? null,
  });
});

app.post('/api/setup/initialize', async (c) => {
  const db = requireDatabase(c.env.DB);
  const body = await readJson<{
    setupKey?: string;
    appName?: string;
    adminName?: string;
    email?: string;
    password?: string;
    rpId?: string;
    origin?: string;
  }>(c);
  await assertSetupKey(c.env.SETUP_KEY, body.setupKey);

  if (await tableExists(db, 'app_meta')) {
    return c.json({ error: 'The application database has already been initialized.' }, 409);
  }

  const appName = requiredText(body.appName, 'Application name', 80);
  const adminName = requiredText(body.adminName, 'Administrator name', 80);
  const email = normalizeEmail(body.email);
  const password = validatePassword(body.password);
  const rpId = validateRpId(body.rpId);
  const origin = validateOrigin(body.origin, rpId);
  const userId = crypto.randomUUID();
  const passwordHash = await hashPassword(password);

  const statements = schemaStatements.map((sql) => db.prepare(sql));
  statements.push(
    db.prepare('INSERT INTO app_meta (key, value) VALUES (?, ?)').bind('schema_version', SCHEMA_VERSION),
    db.prepare('INSERT INTO app_meta (key, value) VALUES (?, ?)').bind('app_name', appName),
    db.prepare('INSERT INTO app_meta (key, value) VALUES (?, ?)').bind('rp_id', rpId),
    db.prepare('INSERT INTO app_meta (key, value) VALUES (?, ?)').bind('origin', origin),
    db.prepare('INSERT INTO app_meta (key, value) VALUES (?, ?)').bind('installation_complete', '1'),
    db.prepare('INSERT INTO app_meta (key, value) VALUES (?, ?)').bind('password_enabled', '1'),
    db.prepare(
      `INSERT INTO users (id, email, display_name, role, password_hash)
       VALUES (?, ?, ?, 'admin', ?)`,
    ).bind(userId, email, adminName, passwordHash),
  );
  await db.batch(statements);
  await recordEvent(c, db, userId, 'setup_initialized', true);
  const token = await createSession(db, userId);
  writeSessionCookie(c, token);

  return c.json({ ok: true, userId });
});

app.post('/api/setup/complete', async (c) => {
  const db = requireDatabase(c.env.DB);
  const body = await readJson<{ setupKey?: string }>(c);
  await assertSetupKey(c.env.SETUP_KEY, body.setupKey);
  const config = await readConfig(db);
  if (config.installationComplete) return c.json({ error: 'Setup is already complete.' }, 409);

  const user = await db.prepare(
    `SELECT id, email, display_name, role, password_hash, created_at
     FROM users WHERE role = 'admin' ORDER BY created_at LIMIT 1`,
  ).first<UserRow>();
  if (!user) return c.json({ error: 'Initial administrator not found.' }, 409);

  await db.prepare(
    `UPDATE app_meta SET value = '1', updated_at = CURRENT_TIMESTAMP WHERE key = 'installation_complete'`,
  ).run();
  await recordEvent(c, db, user.id, 'setup_completed_without_passkey', true);
  const token = await createSession(db, user.id);
  writeSessionCookie(c, token);
  return c.json({ ok: true });
});

app.post('/api/setup/passkey/options', async (c) => {
  const db = requireDatabase(c.env.DB);
  const body = await readJson<{ setupKey?: string }>(c);
  await assertSetupKey(c.env.SETUP_KEY, body.setupKey);
  const config = await readConfig(db);
  if (config.installationComplete) return c.json({ error: 'Setup is already complete.' }, 409);

  const user = await db.prepare(
    `SELECT id, email, display_name, role, password_hash, created_at
     FROM users WHERE role = 'admin' ORDER BY created_at LIMIT 1`,
  ).first<UserRow>();
  if (!user) return c.json({ error: 'Initial administrator not found.' }, 409);

  const result = await createRegistrationChallenge(db, user, config);
  return c.json(result);
});

app.post('/api/setup/passkey/verify', async (c) => {
  const db = requireDatabase(c.env.DB);
  const body = await readJson<{
    setupKey?: string;
    challengeId?: string;
    response?: RegistrationResponseJSON;
    passkeyName?: string;
  }>(c);
  await assertSetupKey(c.env.SETUP_KEY, body.setupKey);
  const config = await readConfig(db);
  if (config.installationComplete) return c.json({ error: 'Setup is already complete.' }, 409);

  const challenge = await consumeChallenge(db, body.challengeId, 'registration');
  const user = await findUserById(db, challenge.user_id);
  if (!body.response) throw new ApiError(400, 'Missing WebAuthn registration response.');

  await verifyAndSaveRegistration(
    db,
    user,
    config,
    challenge.challenge,
    body.response,
    body.passkeyName,
  );
  await db.prepare(
    `UPDATE app_meta SET value = '1', updated_at = CURRENT_TIMESTAMP WHERE key = 'installation_complete'`,
  ).run();
  await recordEvent(c, db, user.id, 'passkey_registered', true, 'Initial setup passkey');
  const token = await createSession(db, user.id);
  writeSessionCookie(c, token);
  return c.json({ ok: true });
});

app.post('/api/auth/login/password', async (c) => {
  const db = requireDatabase(c.env.DB);
  await assertReady(db);
  const body = await readJson<{ email?: string; password?: string }>(c);
  const email = normalizeEmail(body.email);
  const user = await db.prepare(
    `SELECT id, email, display_name, role, password_hash, created_at FROM users WHERE email = ?`,
  ).bind(email).first<UserRow>();

  if (!user?.password_hash || !(await verifyPassword(body.password ?? '', user.password_hash))) {
    await recordEvent(c, db, user?.id ?? null, 'password_login', false);
    return c.json({ error: 'Email or password is incorrect.' }, 401);
  }

  const token = await createSession(db, user.id);
  writeSessionCookie(c, token);
  await recordEvent(c, db, user.id, 'password_login', true);
  return c.json({ ok: true });
});

app.post('/api/auth/login/passkey/options', async (c) => {
  const db = requireDatabase(c.env.DB);
  await assertReady(db);
  const body = await readJson<{ email?: string }>(c);
  const email = normalizeEmail(body.email);
  const user = await db.prepare(
    `SELECT id, email, display_name, role, password_hash, created_at FROM users WHERE email = ?`,
  ).bind(email).first<UserRow>();
  if (!user) return c.json({ error: 'No passkey account was found for this email.' }, 404);

  const credentials = await listCredentials(db, user.id);
  if (!credentials.length) return c.json({ error: 'This account has no registered passkeys.' }, 409);
  const config = await readConfig(db);
  const options = await generateAuthenticationOptions({
    rpID: config.rpId,
    userVerification: 'required',
    allowCredentials: credentials.map((credential) => ({
      id: credential.credential_id as Base64URLString,
      transports: parseTransports(credential.transports),
    })),
  });
  const challengeId = await saveChallenge(db, user.id, options.challenge, 'authentication');
  return c.json({ options, challengeId });
});

app.post('/api/auth/login/passkey/verify', async (c) => {
  const db = requireDatabase(c.env.DB);
  await assertReady(db);
  const body = await readJson<{
    challengeId?: string;
    response?: AuthenticationResponseJSON;
  }>(c);
  const challenge = await consumeChallenge(db, body.challengeId, 'authentication');
  if (!body.response) throw new ApiError(400, 'Missing WebAuthn authentication response.');

  const credential = await db.prepare(
    `SELECT * FROM webauthn_credentials WHERE credential_id = ? AND user_id = ?`,
  ).bind(body.response.id, challenge.user_id).first<CredentialRow>();
  if (!credential) return c.json({ error: 'Passkey is not registered for this account.' }, 401);

  const config = await readConfig(db);
  const verification = await verifyAuthenticationResponse({
    response: body.response,
    expectedChallenge: challenge.challenge,
    expectedOrigin: config.origin,
    expectedRPID: config.rpId,
    requireUserVerification: true,
    credential: {
      id: credential.credential_id as Base64URLString,
      publicKey: base64urlToBytes(credential.public_key),
      counter: credential.counter,
      transports: parseTransports(credential.transports),
    },
  });
  if (!verification.verified) {
    await recordEvent(c, db, challenge.user_id, 'passkey_login', false);
    return c.json({ error: 'Passkey verification failed.' }, 401);
  }

  await db.prepare(
    `UPDATE webauthn_credentials
     SET counter = ?, last_used_at = CURRENT_TIMESTAMP WHERE id = ?`,
  ).bind(verification.authenticationInfo.newCounter, credential.id).run();
  const token = await createSession(db, challenge.user_id);
  writeSessionCookie(c, token);
  await recordEvent(c, db, challenge.user_id, 'passkey_login', true, credential.name);
  return c.json({ ok: true });
});

app.get('/api/auth/me', async (c) => {
  const user = c.get('user');
  return c.json({
    user: {
      id: user.id,
      email: user.email,
      displayName: user.display_name,
      role: user.role,
    },
  });
});

app.post('/api/auth/logout', async (c) => {
  const db = requireDatabase(c.env.DB);
  const token = getCookie(c, SESSION_COOKIE);
  if (token) {
    await db.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(await sha256(token)).run();
  }
  deleteCookie(c, SESSION_COOKIE, { path: '/' });
  return c.json({ ok: true });
});

app.get('/api/auth/passkeys', async (c) => {
  const db = requireDatabase(c.env.DB);
  const credentials = await listCredentials(db, c.get('user').id);
  return c.json({
    passkeys: credentials.map((credential) => ({
      id: credential.id,
      name: credential.name,
      deviceType: credential.device_type,
      backedUp: Boolean(credential.backed_up),
      createdAt: credential.created_at,
      lastUsedAt: credential.last_used_at,
    })),
  });
});

app.post('/api/auth/passkeys/register/options', async (c) => {
  const db = requireDatabase(c.env.DB);
  const config = await readConfig(db);
  return c.json(await createRegistrationChallenge(db, c.get('user'), config));
});

app.post('/api/auth/passkeys/register/verify', async (c) => {
  const db = requireDatabase(c.env.DB);
  const body = await readJson<{
    challengeId?: string;
    response?: RegistrationResponseJSON;
    passkeyName?: string;
  }>(c);
  const user = c.get('user');
  const challenge = await consumeChallenge(db, body.challengeId, 'registration', user.id);
  if (!body.response) throw new ApiError(400, 'Missing WebAuthn registration response.');
  const config = await readConfig(db);
  await verifyAndSaveRegistration(
    db,
    user,
    config,
    challenge.challenge,
    body.response,
    body.passkeyName,
  );
  await recordEvent(c, db, user.id, 'passkey_registered', true);
  return c.json({ ok: true });
});

app.patch('/api/auth/passkeys/:id', async (c) => {
  const db = requireDatabase(c.env.DB);
  const body = await readJson<{ name?: string }>(c);
  const name = requiredText(body.name, 'Passkey name', 60);
  const result = await db.prepare(
    `UPDATE webauthn_credentials SET name = ? WHERE id = ? AND user_id = ?`,
  ).bind(name, c.req.param('id'), c.get('user').id).run();
  if (!result.meta.changes) return c.json({ error: 'Passkey not found.' }, 404);
  return c.json({ ok: true });
});

app.delete('/api/auth/passkeys/:id', async (c) => {
  const db = requireDatabase(c.env.DB);
  const user = c.get('user');
  const count = await db.prepare(
    'SELECT COUNT(*) AS total FROM webauthn_credentials WHERE user_id = ?',
  ).bind(user.id).first<{ total: number }>();
  if ((count?.total ?? 0) <= 1) {
    return c.json({ error: 'Register another passkey before removing your last passkey.' }, 409);
  }
  const result = await db.prepare(
    'DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?',
  ).bind(c.req.param('id'), user.id).run();
  if (!result.meta.changes) return c.json({ error: 'Passkey not found.' }, 404);
  await recordEvent(c, db, user.id, 'passkey_removed', true);
  return c.json({ ok: true });
});

app.notFound((c) => {
  if (c.req.path.startsWith('/api/')) return c.json({ error: 'API route not found.' }, 404);
  return c.env.ASSETS.fetch(c.req.raw);
});

app.onError((error, c) => {
  console.error(error);
  if (error instanceof ApiError) return c.json({ error: error.message }, error.status);
  const message = error instanceof Error ? error.message : 'Unexpected server error.';
  return c.json({ error: message }, 500);
});

class ApiError extends Error {
  constructor(public status: 400 | 401 | 403 | 404 | 409 | 500 | 503, message: string) {
    super(message);
  }
}

function requireDatabase(db?: D1Database): D1Database {
  if (!db) throw new ApiError(503, 'The D1 binding named DB is not configured.');
  return db;
}

async function readJson<T>(c: { req: { json: () => Promise<unknown> } }): Promise<T> {
  try {
    return (await c.req.json()) as T;
  } catch {
    throw new ApiError(400, 'Request body must be valid JSON.');
  }
}

async function tableExists(db: D1Database, name: string): Promise<boolean> {
  const row = await db.prepare(
    `SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`,
  ).bind(name).first();
  return Boolean(row);
}

async function readConfig(db: D1Database): Promise<AppConfig> {
  const result = await db.prepare('SELECT key, value FROM app_meta').all<{ key: string; value: string }>();
  const values = Object.fromEntries(result.results.map((row) => [row.key, row.value]));
  if (!values.rp_id || !values.origin) throw new ApiError(409, 'Application setup is incomplete.');
  return {
    appName: values.app_name || 'Passkey Lab',
    rpId: values.rp_id,
    origin: values.origin,
    installationComplete: values.installation_complete === '1',
    passwordEnabled: values.password_enabled !== '0',
  };
}

async function assertReady(db: D1Database): Promise<void> {
  if (!(await tableExists(db, 'app_meta'))) throw new ApiError(409, 'Application setup is required.');
  if (!(await readConfig(db)).installationComplete) throw new ApiError(409, 'Register the initial passkey to finish setup.');
}

async function assertSetupKey(expected?: string, supplied?: string): Promise<void> {
  if (!expected) throw new ApiError(503, 'SETUP_KEY is not configured on the Worker.');
  if (!supplied || !(await safeEqual(expected, supplied))) {
    throw new ApiError(403, 'The setup key is incorrect.');
  }
}

async function safeEqual(left: string, right: string): Promise<boolean> {
  const [a, b] = await Promise.all([sha256(left), sha256(right)]);
  let mismatch = a.length ^ b.length;
  for (let index = 0; index < Math.max(a.length, b.length); index += 1) {
    mismatch |= (a.charCodeAt(index) || 0) ^ (b.charCodeAt(index) || 0);
  }
  return mismatch === 0;
}

function requiredText(value: string | undefined, label: string, max: number): string {
  const normalized = value?.trim();
  if (!normalized) throw new ApiError(400, `${label} is required.`);
  if (normalized.length > max) throw new ApiError(400, `${label} is too long.`);
  return normalized;
}

function normalizeEmail(value?: string): string {
  const email = value?.trim().toLowerCase() ?? '';
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new ApiError(400, 'Enter a valid email address.');
  return email;
}

function validatePassword(value?: string): string {
  if (!value || value.length < 10) throw new ApiError(400, 'Password must contain at least 10 characters.');
  if (value.length > 128) throw new ApiError(400, 'Password is too long.');
  return value;
}

function validateRpId(value?: string): string {
  const rpId = value?.trim().toLowerCase() ?? '';
  if (!rpId || rpId.includes('://') || rpId.includes('/') || rpId.includes(':')) {
    throw new ApiError(400, 'RP ID must be a hostname without a protocol, port or path.');
  }
  return rpId;
}

function validateOrigin(value: string | undefined, rpId: string): string {
  try {
    const url = new URL(value ?? '');
    const local = url.hostname === 'localhost' || url.hostname === '127.0.0.1';
    if (url.protocol !== 'https:' && !local) throw new Error('HTTPS required');
    if (url.pathname !== '/' || url.search || url.hash) throw new Error('Origin only');
    if (url.hostname !== rpId && !url.hostname.endsWith(`.${rpId}`)) throw new Error('RP mismatch');
    return url.origin;
  } catch {
    throw new ApiError(400, 'Origin must be an HTTPS origin that matches the RP ID.');
  }
}

async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iterations = 100_000;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    key,
    256,
  );
  return `pbkdf2_sha256$${iterations}$${bytesToBase64url(salt)}$${bytesToBase64url(new Uint8Array(bits))}`;
}

async function verifyPassword(password: string, encoded: string): Promise<boolean> {
  const [algorithm, iterationText, saltText, expected] = encoded.split('$');
  if (algorithm !== 'pbkdf2_sha256' || !iterationText || !saltText || !expected) return false;
  const iterations = Number(iterationText);
  if (!Number.isSafeInteger(iterations) || iterations < 100_000) return false;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: base64urlToBytes(saltText), iterations },
    key,
    256,
  );
  return safeEqual(bytesToBase64url(new Uint8Array(bits)), expected);
}

async function createRegistrationChallenge(db: D1Database, user: UserRow, config: AppConfig) {
  const credentials = await listCredentials(db, user.id);
  const options = await generateRegistrationOptions({
    rpName: config.appName,
    rpID: config.rpId,
    userName: user.email,
    userDisplayName: user.display_name,
    userID: new TextEncoder().encode(user.id),
    attestationType: 'none',
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'required',
    },
    excludeCredentials: credentials.map((credential) => ({
      id: credential.credential_id as Base64URLString,
      transports: parseTransports(credential.transports),
    })),
  });
  const challengeId = await saveChallenge(db, user.id, options.challenge, 'registration');
  return { options, challengeId };
}

async function verifyAndSaveRegistration(
  db: D1Database,
  user: UserRow,
  config: AppConfig,
  challenge: string,
  response: RegistrationResponseJSON,
  passkeyName?: string,
): Promise<void> {
  const verification = await verifyRegistrationResponse({
    response,
    expectedChallenge: challenge,
    expectedOrigin: config.origin,
    expectedRPID: config.rpId,
    requireUserVerification: true,
  });
  if (!verification.verified) throw new ApiError(401, 'Passkey registration could not be verified.');

  const info = verification.registrationInfo;
  const name = passkeyName?.trim().slice(0, 60) || defaultPasskeyName(response.response.transports);
  await db.prepare(
    `INSERT INTO webauthn_credentials
      (id, user_id, credential_id, public_key, counter, transports, device_type, backed_up, name)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).bind(
    crypto.randomUUID(),
    user.id,
    info.credential.id,
    bytesToBase64url(info.credential.publicKey),
    info.credential.counter,
    JSON.stringify(response.response.transports ?? []),
    info.credentialDeviceType,
    info.credentialBackedUp ? 1 : 0,
    name,
  ).run();
}

function defaultPasskeyName(transports?: string[]): string {
  if (transports?.includes('internal')) return 'This device';
  if (transports?.includes('usb')) return 'Security key';
  return 'Passkey';
}

async function saveChallenge(db: D1Database, userId: string, challenge: string, purpose: string): Promise<string> {
  await db.prepare('DELETE FROM webauthn_challenges WHERE expires_at <= CURRENT_TIMESTAMP').run();
  const id = crypto.randomUUID();
  await db.prepare(
    `INSERT INTO webauthn_challenges (id, user_id, challenge, purpose, expires_at)
     VALUES (?, ?, ?, ?, datetime('now', ?))`,
  ).bind(id, userId, challenge, purpose, `+${CHALLENGE_TTL_MINUTES} minutes`).run();
  return id;
}

async function consumeChallenge(
  db: D1Database,
  id: string | undefined,
  purpose: string,
  expectedUserId?: string,
): Promise<{ user_id: string; challenge: string }> {
  if (!id) throw new ApiError(400, 'Missing challenge identifier.');
  const row = await db.prepare(
    `SELECT user_id, challenge FROM webauthn_challenges
     WHERE id = ? AND purpose = ? AND expires_at > CURRENT_TIMESTAMP`,
  ).bind(id, purpose).first<{ user_id: string; challenge: string }>();
  await db.prepare('DELETE FROM webauthn_challenges WHERE id = ?').bind(id).run();
  if (!row || (expectedUserId && row.user_id !== expectedUserId)) {
    throw new ApiError(401, 'The authentication request expired. Please try again.');
  }
  return row;
}

async function listCredentials(db: D1Database, userId: string): Promise<CredentialRow[]> {
  const result = await db.prepare(
    'SELECT * FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at DESC',
  ).bind(userId).all<CredentialRow>();
  return result.results;
}

function parseTransports(value: string | null): string[] {
  if (!value) return [];
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed.filter((item) => typeof item === 'string') : [];
  } catch {
    return [];
  }
}

async function findUserById(db: D1Database, id: string): Promise<UserRow> {
  const user = await db.prepare(
    `SELECT id, email, display_name, role, password_hash, created_at FROM users WHERE id = ?`,
  ).bind(id).first<UserRow>();
  if (!user) throw new ApiError(404, 'User not found.');
  return user;
}

async function createSession(db: D1Database, userId: string): Promise<string> {
  await db.prepare('DELETE FROM sessions WHERE expires_at <= CURRENT_TIMESTAMP').run();
  const token = bytesToBase64url(crypto.getRandomValues(new Uint8Array(32)));
  await db.prepare(
    `INSERT INTO sessions (id, user_id, token_hash, expires_at)
     VALUES (?, ?, ?, datetime('now', ?))`,
  ).bind(crypto.randomUUID(), userId, await sha256(token), `+${SESSION_TTL_DAYS} days`).run();
  return token;
}

function writeSessionCookie(c: Parameters<typeof setCookie>[0], token: string): void {
  setCookie(c, SESSION_COOKIE, token, {
    httpOnly: true,
    secure: true,
    sameSite: 'Lax',
    path: '/',
    maxAge: SESSION_TTL_DAYS * 24 * 60 * 60,
  });
}

async function authenticatedUser(
  c: Parameters<typeof getCookie>[0],
  db: D1Database,
): Promise<UserRow | null> {
  const token = getCookie(c, SESSION_COOKIE);
  if (!token) return null;
  const user = await db.prepare(
    `SELECT u.id, u.email, u.display_name, u.role, u.password_hash, u.created_at
     FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = ? AND s.expires_at > CURRENT_TIMESTAMP`,
  ).bind(await sha256(token)).first<UserRow>();
  return user ?? null;
}

async function recordEvent(
  c: { req: { header: (name: string) => string | undefined } },
  db: D1Database,
  userId: string | null,
  eventType: string,
  success: boolean,
  detail?: string,
): Promise<void> {
  await db.prepare(
    `INSERT INTO authentication_events (id, user_id, event_type, success, detail, ip_address)
     VALUES (?, ?, ?, ?, ?, ?)`,
  ).bind(
    crypto.randomUUID(),
    userId,
    eventType,
    success ? 1 : 0,
    detail ?? null,
    c.req.header('CF-Connecting-IP') ?? null,
  ).run();
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return bytesToBase64url(new Uint8Array(digest));
}

function bytesToBase64url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64urlToBytes(value: string): Uint8Array<ArrayBuffer> {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

export default app;
