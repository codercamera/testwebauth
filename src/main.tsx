import { FormEvent, ReactNode, useCallback, useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { startAuthentication, startRegistration } from '@simplewebauthn/browser';
import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/browser';
import './styles.css';

type SetupStatus = {
  state: 'missing_database' | 'empty' | 'awaiting_passkey' | 'ready';
  setupKeyConfigured: boolean;
  message?: string;
  config?: {
    appName: string;
    rpId: string;
    origin: string;
    installationComplete: boolean;
  };
  admin?: { id: string; email: string; display_name: string } | null;
};

type User = { id: string; email: string; displayName: string; role: string };
type Passkey = {
  id: string;
  name: string;
  deviceType: string | null;
  backedUp: boolean;
  createdAt: string;
  lastUsedAt: string | null;
};
type GoogleConnection = {
  configured: boolean;
  account: {
    email: string;
    displayName: string | null;
    pictureUrl: string | null;
    connectedAt: string;
    lastLoginAt: string | null;
  } | null;
};

type Screen =
  | { type: 'loading' }
  | { type: 'database-missing'; status: SetupStatus }
  | { type: 'setup'; status: SetupStatus }
  | { type: 'login'; status: SetupStatus }
  | { type: 'app'; status: SetupStatus; user: User };

function App() {
  const [screen, setScreen] = useState<Screen>({ type: 'loading' });
  const [notice, setNotice] = useState<string | null>(null);
  const [googleRecoveryEmail, setGoogleRecoveryEmail] = useState<string | null>(null);

  const boot = useCallback(async () => {
    setScreen({ type: 'loading' });
    try {
      const status = await api<SetupStatus>('/api/setup/status');
      if (status.state === 'missing_database') return setScreen({ type: 'database-missing', status });
      if (status.state === 'empty' || status.state === 'awaiting_passkey') {
        return setScreen({ type: 'setup', status });
      }
      try {
        const response = await api<{ user: User }>('/api/auth/me');
        setScreen({ type: 'app', status, user: response.user });
      } catch (error) {
        if (error instanceof ApiClientError && error.status === 401) {
          setScreen({ type: 'login', status });
        } else {
          throw error;
        }
      }
    } catch (error) {
      setNotice(errorMessage(error));
      setScreen({ type: 'database-missing', status: { state: 'missing_database', setupKeyConfigured: false } });
    }
  }, []);

  useEffect(() => { void boot(); }, [boot]);
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const missingEmail = params.get('oauth_missing');
    if (missingEmail) setGoogleRecoveryEmail(missingEmail);
    const message = params.get('oauth') ?? params.get('oauth_error');
    if (message) {
      setNotice(message);
      window.history.replaceState({}, '', window.location.pathname);
    }
  }, []);

  return (
    <div className="app-shell">
      {notice && <Toast message={notice} onClose={() => setNotice(null)} />}
      {screen.type === 'loading' && <LoadingScreen />}
      {screen.type === 'database-missing' && <DatabaseMissing status={screen.status} onRetry={boot} />}
      {screen.type === 'setup' && (
        <SetupWizard
          status={screen.status}
          onComplete={() => { setNotice('Setup complete. You can add a passkey from Security settings.'); void boot(); }}
          onError={(message) => setNotice(message)}
        />
      )}
      {screen.type === 'login' && (
        <LoginScreen
          appName={screen.status.config?.appName ?? 'Passkey Lab'}
          recoveryEmail={googleRecoveryEmail}
          onSuccess={() => void boot()}
          onError={(message) => setNotice(message)}
        />
      )}
      {screen.type === 'app' && (
        <AuthenticatedApp
          user={screen.user}
          appName={screen.status.config?.appName ?? 'Passkey Lab'}
          onLogout={() => void boot()}
          onNotice={setNotice}
        />
      )}
    </div>
  );
}

function LoadingScreen() {
  return (
    <main className="center-page">
      <Brand />
      <div className="loader" aria-label="Loading" />
      <p className="muted">Checking application status…</p>
    </main>
  );
}

function DatabaseMissing({ status, onRetry }: { status: SetupStatus; onRetry: () => void }) {
  return (
    <main className="center-page page-padding">
      <Brand />
      <section className="card setup-card">
        <StepBadge icon="database" />
        <p className="eyebrow">Configuration required</p>
        <h1>Connect a D1 database</h1>
        <p className="lead">The application needs a Cloudflare D1 binding named <code>DB</code> before it can create its tables.</p>
        <div className="check-list">
          <CheckRow done={false}>Create a D1 database in Cloudflare</CheckRow>
          <CheckRow done={false}>Attach the D1 binding as <code>DB</code></CheckRow>
          <CheckRow done={status.setupKeyConfigured}>Configure the <code>SETUP_KEY</code> Worker secret</CheckRow>
          <CheckRow done={false}>Deploy the Worker again</CheckRow>
        </div>
        {status.message && <div className="inline-warning">{status.message}</div>}
        <button className="button primary full" onClick={onRetry}>Check again</button>
      </section>
    </main>
  );
}

function SetupWizard({ status, onComplete, onError }: {
  status: SetupStatus;
  onComplete: () => void;
  onError: (message: string) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [setupKey, setSetupKey] = useState('');
  const [form, setForm] = useState({
    appName: 'Passkey Lab',
    adminName: '',
    email: '',
    password: '',
    rpId: window.location.hostname,
    origin: window.location.origin,
  });

  async function initialize(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      await api('/api/setup/initialize', { method: 'POST', body: { ...form, setupKey } });
      onComplete();
    } catch (error) {
      onError(errorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  async function completePreviousSetup() {
    setBusy(true);
    try {
      await api('/api/setup/complete', { method: 'POST', body: { setupKey } });
      onComplete();
    } catch (error) {
      onError(errorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="center-page page-padding">
      <Brand />
      {status.state === 'empty' ? (
        <form className="card setup-card" onSubmit={initialize}>
          <p className="eyebrow">Initial setup</p>
          <h1>Initialize your app</h1>
          <p className="lead">Create the database tables and the first administrator. You can add a passkey later from Security settings.</p>
          {!status.setupKeyConfigured && <div className="inline-warning">Configure <code>SETUP_KEY</code> before continuing.</div>}
          <Field label="Setup key">
            <input type="password" value={setupKey} onChange={(e) => setSetupKey(e.target.value)} required autoComplete="off" />
          </Field>
          <Field label="Application name">
            <input value={form.appName} onChange={(e) => setForm({ ...form, appName: e.target.value })} required maxLength={80} />
          </Field>
          <div className="field-grid">
            <Field label="RP ID" hint="Hostname only">
              <input value={form.rpId} onChange={(e) => setForm({ ...form, rpId: e.target.value })} required />
            </Field>
            <Field label="Expected origin" hint="Exact HTTPS origin">
              <input value={form.origin} onChange={(e) => setForm({ ...form, origin: e.target.value })} required />
            </Field>
          </div>
          <div className="section-divider"><span>First administrator</span></div>
          <Field label="Name">
            <input value={form.adminName} onChange={(e) => setForm({ ...form, adminName: e.target.value })} required autoComplete="name" />
          </Field>
          <Field label="Email">
            <input type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} required autoComplete="email" />
          </Field>
          <Field label="Temporary password" hint="At least 10 characters">
            <input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} minLength={10} required autoComplete="new-password" />
          </Field>
          <button className="button primary full" disabled={busy}>{busy ? 'Creating tables…' : 'Create application'}</button>
        </form>
      ) : (
        <section className="card setup-card">
          <StepBadge icon="shield" />
          <p className="eyebrow">Setup update</p>
          <h1>Finish setup</h1>
          <p className="lead">This installation was created by an earlier version that required a passkey. You can now finish setup without registering one.</p>
          {status.admin && (
            <div className="identity-chip">
              <Avatar name={status.admin.display_name} />
              <div><strong>{status.admin.display_name}</strong><span>{status.admin.email}</span></div>
            </div>
          )}
          <Field label="Setup key">
            <input type="password" value={setupKey} onChange={(e) => setSetupKey(e.target.value)} required autoComplete="off" />
          </Field>
          <button className="button primary full" onClick={completePreviousSetup} disabled={busy || !setupKey}>
            {busy ? 'Finishing setup…' : 'Finish without passkey'}
          </button>
        </section>
      )}
    </main>
  );
}

function LoginScreen({ appName, recoveryEmail, onSuccess, onError }: {
  appName: string;
  recoveryEmail?: string | null;
  onSuccess: () => void;
  onError: (message: string) => void;
}) {
  const [mode, setMode] = useState<'passkey' | 'password'>('password');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [googleAvailable, setGoogleAvailable] = useState(false);

  useEffect(() => {
    void api<{ google: boolean }>('/api/auth/providers')
      .then((providers) => setGoogleAvailable(providers.google))
      .catch(() => setGoogleAvailable(false));
  }, []);

  if (recoveryEmail) {
    return <GoogleRecoveryScreen email={recoveryEmail} />;
  }

  async function login(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      if (mode === 'password') {
        await api('/api/auth/login/password', { method: 'POST', body: { email, password } });
      } else {
        const challenge = await api<AuthenticationChallenge>('/api/auth/login/passkey/options', {
          method: 'POST', body: { email },
        });
        const response = await startAuthentication({ optionsJSON: challenge.options });
        await api('/api/auth/login/passkey/verify', {
          method: 'POST', body: { challengeId: challenge.challengeId, response },
        });
      }
      onSuccess();
    } catch (error) {
      if (isUserCancelled(error)) onError('Authentication was cancelled.');
      else onError(errorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="login-page page-padding">
      <div className="login-hero">
        <Brand name={appName} />
        <p>Secure sign-in without sharing a secret.</p>
      </div>
      <form className="card login-card" onSubmit={login}>
        <h1>Welcome back</h1>
        <p className="lead">Choose how you want to sign in.</p>
        {googleAvailable && (
          <>
            <button className="button google-button full" type="button" onClick={() => window.location.assign('/api/auth/google/start')}>
              <GoogleIcon /> Continue with Google
            </button>
            <button className="google-signup-link" type="button" onClick={() => window.location.assign('/api/auth/google/start?mode=signup')}>
              New user? Sign up with Google
            </button>
            <div className="auth-divider"><span>or</span></div>
          </>
        )}
        <div className="mode-tabs">
          <button type="button" className={mode === 'passkey' ? 'active' : ''} onClick={() => setMode('passkey')}>Passkey</button>
          <button type="button" className={mode === 'password' ? 'active' : ''} onClick={() => setMode('password')}>Password</button>
        </div>
        <Field label="Email">
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required autoComplete="username webauthn" />
        </Field>
        {mode === 'password' && (
          <Field label="Password">
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required autoComplete="current-password" />
          </Field>
        )}
        <button className="button primary full" disabled={busy}>
          {mode === 'passkey' && <Icon name="fingerprint" />}
          {busy ? 'Please wait…' : mode === 'passkey' ? 'Sign in with passkey' : 'Sign in'}
        </button>
        {mode === 'passkey' && <p className="tiny centered">Your device may ask for your fingerprint, face or PIN.</p>}
      </form>
    </main>
  );
}

function GoogleRecoveryScreen({ email }: { email: string }) {
  return (
    <main className="login-page page-padding">
      <div className="login-hero">
        <Brand name="Passkey Lab" />
        <p>Secure sign-in without sharing a secret.</p>
      </div>
      <section className="card recovery-card">
        <div className="recovery-icon"><Icon name="database" /></div>
        <h1>No account found</h1>
        <p className="lead">We checked this Google account:</p>
        <div className="google-account-row"><GoogleIcon /><strong>{email}</strong></div>
        <p className="recovery-explanation">There isn’t a Passkey Lab account for this email yet.</p>
        <button className="button primary full" type="button" onClick={() => window.location.assign('/api/auth/google/start?mode=signup')}>
          <GoogleIcon /> Create account with Google
        </button>
        <p className="tiny centered">Creates a standard user account. No password required.</p>
        <button className="button recovery-secondary full" type="button" onClick={() => window.location.assign('/api/auth/google/start')}>
          Use a different Google account
        </button>
        <button className="recovery-back" type="button" onClick={() => window.location.assign('/')}>
          Back to sign in
        </button>
        <div className="privacy-note"><Icon name="shield" /><span>Google only shares your verified email and basic profile.</span></div>
      </section>
    </main>
  );
}

function AuthenticatedApp({ user, appName, onLogout, onNotice }: {
  user: User;
  appName: string;
  onLogout: () => void;
  onNotice: (message: string) => void;
}) {
  const [tab, setTab] = useState<'home' | 'security'>('home');

  async function logout() {
    try { await api('/api/auth/logout', { method: 'POST' }); onLogout(); }
    catch (error) { onNotice(errorMessage(error)); }
  }

  return (
    <div className="authenticated-shell">
      <header className="topbar">
        <Brand compact name={appName} />
        <button className="avatar-button" onClick={() => setTab('security')} aria-label="Open account settings"><Avatar name={user.displayName} /></button>
      </header>
      <main className="content-page">
        {tab === 'home' ? (
          <section className="empty-dashboard">
            <div className="welcome-row"><div><p className="eyebrow">Dashboard</p><h1>Hello, {firstName(user.displayName)}</h1></div><span className="status-pill"><i /> Signed in</span></div>
            <div className="blank-state"><div className="blank-icon"><Icon name="grid" /></div><h2>Your dashboard is ready</h2><p>This area is intentionally blank while you test authentication.</p></div>
          </section>
        ) : (
          <SecuritySettings user={user} onNotice={onNotice} onLogout={logout} />
        )}
      </main>
      <nav className="bottom-nav" aria-label="Main navigation">
        <button className={tab === 'home' ? 'active' : ''} onClick={() => setTab('home')}><Icon name="home" /><span>Home</span></button>
        <button className={tab === 'security' ? 'active' : ''} onClick={() => setTab('security')}><Icon name="shield" /><span>Security</span></button>
      </nav>
    </div>
  );
}

function SecuritySettings({ user, onNotice, onLogout }: {
  user: User;
  onNotice: (message: string) => void;
  onLogout: () => void;
}) {
  const [passkeys, setPasskeys] = useState<Passkey[]>([]);
  const [google, setGoogle] = useState<GoogleConnection>({ configured: false, account: null });
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [passkeyResponse, googleResponse] = await Promise.all([
        api<{ passkeys: Passkey[] }>('/api/auth/passkeys'),
        api<GoogleConnection>('/api/auth/google/account'),
      ]);
      setPasskeys(passkeyResponse.passkeys);
      setGoogle(googleResponse);
    }
    catch (error) { onNotice(errorMessage(error)); }
    finally { setLoading(false); }
  }, [onNotice]);

  useEffect(() => { void load(); }, [load]);

  async function addPasskey() {
    setBusy(true);
    try {
      const challenge = await api<RegistrationChallenge>('/api/auth/passkeys/register/options', { method: 'POST' });
      const response = await startRegistration({ optionsJSON: challenge.options });
      await api('/api/auth/passkeys/register/verify', {
        method: 'POST', body: { challengeId: challenge.challengeId, response },
      });
      onNotice('A new passkey was added.');
      await load();
    } catch (error) {
      if (isUserCancelled(error)) onNotice('Passkey creation was cancelled.');
      else onNotice(errorMessage(error));
    } finally { setBusy(false); }
  }

  async function rename(passkey: Passkey) {
    const name = window.prompt('Passkey name', passkey.name)?.trim();
    if (!name || name === passkey.name) return;
    try {
      await api(`/api/auth/passkeys/${passkey.id}`, { method: 'PATCH', body: { name } });
      await load();
    } catch (error) { onNotice(errorMessage(error)); }
  }

  async function remove(passkey: Passkey) {
    if (!window.confirm(`Remove “${passkey.name}”? You will no longer be able to sign in with it.`)) return;
    try {
      await api(`/api/auth/passkeys/${passkey.id}`, { method: 'DELETE' });
      onNotice('Passkey removed.');
      await load();
    } catch (error) { onNotice(errorMessage(error)); }
  }

  function connectGoogle() {
    window.location.assign('/api/auth/google/start?mode=link');
  }

  async function disconnectGoogle() {
    if (!window.confirm('Disconnect this Google account? Password and passkey sign-in will remain available.')) return;
    try {
      await api('/api/auth/google/account', { method: 'DELETE' });
      onNotice('Google account disconnected.');
      await load();
    } catch (error) { onNotice(errorMessage(error)); }
  }

  return (
    <section className="settings-page">
      <div><p className="eyebrow">Account</p><h1>Security</h1><p className="lead">Manage how you sign in to this application.</p></div>
      <div className="profile-card"><Avatar name={user.displayName} /><div><strong>{user.displayName}</strong><span>{user.email}</span></div><span className="role-badge">{user.role}</span></div>
      <section className="settings-section">
        <div className="section-heading">
          <div><h2>Google account</h2><p>{google.account ? `Connected as ${google.account.email}` : 'Use Google as an additional sign-in method.'}</p></div>
          {google.configured && (google.account ? (
            <button className="button secondary small" onClick={disconnectGoogle}>Disconnect</button>
          ) : (
            <button className="button secondary small" onClick={connectGoogle}><GoogleIcon /> Connect</button>
          ))}
        </div>
        {!google.configured && <div className="list-placeholder">Google OAuth is not configured on this Worker.</div>}
        {google.account && (
          <div className="provider-account">
            {google.account.pictureUrl ? <img src={google.account.pictureUrl} alt="" referrerPolicy="no-referrer" /> : <GoogleIcon />}
            <div><strong>{google.account.displayName || user.displayName}</strong><span>{google.account.email}</span></div>
            <span className="enabled-badge">Connected</span>
          </div>
        )}
      </section>
      <section className="settings-section">
        <div className="section-heading"><div><h2>Passkeys</h2><p>Use your devices to sign in securely.</p></div><button className="button secondary small" onClick={addPasskey} disabled={busy}><Icon name="plus" /> Add</button></div>
        {loading ? <div className="list-placeholder">Loading passkeys…</div> : passkeys.length === 0 ? (
          <div className="list-placeholder">No passkeys registered yet. Select Add to test WebAuthn on this device.</div>
        ) : passkeys.map((passkey) => (
          <article className="passkey-row" key={passkey.id}>
            <div className="passkey-symbol"><Icon name="passkey" /></div>
            <div className="passkey-info"><strong>{passkey.name}</strong><span>{passkey.backedUp ? 'Synced passkey' : 'Device passkey'} · Added {formatDate(passkey.createdAt)}</span>{passkey.lastUsedAt && <small>Last used {formatDate(passkey.lastUsedAt)}</small>}</div>
            <div className="row-actions"><button onClick={() => rename(passkey)} aria-label={`Rename ${passkey.name}`}><Icon name="edit" /></button><button onClick={() => remove(passkey)} aria-label={`Remove ${passkey.name}`}><Icon name="trash" /></button></div>
          </article>
        ))}
      </section>
      <section className="settings-section"><div className="section-heading"><div><h2>Password fallback</h2><p>Enabled for testing and account recovery.</p></div><span className="enabled-badge">Enabled</span></div></section>
      <button className="button danger-text full" onClick={onLogout}><Icon name="logout" /> Sign out</button>
    </section>
  );
}

type RegistrationChallenge = { options: PublicKeyCredentialCreationOptionsJSON; challengeId: string };
type AuthenticationChallenge = { options: PublicKeyCredentialRequestOptionsJSON; challengeId: string };

async function api<T = { ok: boolean }>(path: string, options: { method?: string; body?: unknown } = {}): Promise<T> {
  const response = await fetch(path, {
    method: options.method ?? 'GET',
    headers: options.body ? { 'Content-Type': 'application/json' } : undefined,
    body: options.body ? JSON.stringify(options.body) : undefined,
    credentials: 'same-origin',
  });
  const payload = await response.json().catch(() => ({})) as { error?: string } & T;
  if (!response.ok) throw new ApiClientError(response.status, payload.error ?? 'The request failed.');
  return payload;
}

class ApiClientError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'Something went wrong. Please try again.';
}

function isUserCancelled(error: unknown): boolean {
  return error instanceof Error && (error.name === 'NotAllowedError' || /cancel|timed out/i.test(error.message));
}

function Brand({ compact = false, name = 'Passkey Lab' }: { compact?: boolean; name?: string }) {
  return <div className={`brand ${compact ? 'compact' : ''}`}><span className="brand-mark"><Icon name="passkey" /></span><span>{name}</span></div>;
}

function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return <label className="field"><span>{label}{hint && <small>{hint}</small>}</span>{children}</label>;
}

function CheckRow({ done, children }: { done: boolean; children: ReactNode }) {
  return <div className={`check-row ${done ? 'done' : ''}`}><span>{done ? '✓' : '○'}</span><div>{children}</div></div>;
}

function StepBadge({ icon }: { icon: IconName }) { return <div className="step-badge"><Icon name={icon} /></div>; }
function Avatar({ name }: { name: string }) { return <span className="avatar">{name.trim().charAt(0).toUpperCase() || '?'}</span>; }
function GoogleIcon() {
  return (
    <svg className="google-icon" viewBox="0 0 24 24" aria-hidden="true">
      <path fill="#4285F4" d="M21.6 12.23c0-.71-.06-1.4-.18-2.07H12v3.92h5.38a4.6 4.6 0 0 1-2 3.02v2.54h3.24c1.9-1.75 2.98-4.33 2.98-7.41Z"/>
      <path fill="#34A853" d="M12 22c2.7 0 4.97-.9 6.63-2.43l-3.24-2.54c-.9.6-2.05.96-3.39.96-2.61 0-4.82-1.76-5.61-4.13H3.04v2.62A10 10 0 0 0 12 22Z"/>
      <path fill="#FBBC05" d="M6.39 13.86A6 6 0 0 1 6.08 12c0-.65.11-1.28.31-1.86V7.52H3.04A10 10 0 0 0 2 12c0 1.61.39 3.14 1.04 4.48l3.35-2.62Z"/>
      <path fill="#EA4335" d="M12 6.01c1.47 0 2.79.5 3.82 1.5l2.87-2.87A9.63 9.63 0 0 0 12 2 10 10 0 0 0 3.04 7.52l3.35 2.62C7.18 7.77 9.39 6.01 12 6.01Z"/>
    </svg>
  );
}
function Toast({ message, onClose }: { message: string; onClose: () => void }) {
  useEffect(() => { const timer = window.setTimeout(onClose, 5000); return () => window.clearTimeout(timer); }, [onClose]);
  return <div className="toast" role="status"><span>{message}</span><button onClick={onClose} aria-label="Close">×</button></div>;
}

type IconName = 'database' | 'passkey' | 'shield' | 'fingerprint' | 'grid' | 'home' | 'plus' | 'edit' | 'trash' | 'logout';
function Icon({ name }: { name: IconName }) {
  const paths: Record<IconName, ReactNode> = {
    database: <><ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v6c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 11v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6"/></>,
    passkey: <><circle cx="8.5" cy="9" r="4"/><path d="M12 9h8v3h-2v2h-3v-2h-3M8.5 7.5v3"/></>,
    shield: <path d="M12 3 4.5 6v5.2c0 4.6 3.2 8.8 7.5 9.8 4.3-1 7.5-5.2 7.5-9.8V6L12 3Zm-3 9 2 2 4-4"/>,
    fingerprint: <><path d="M6.2 9.5A6.2 6.2 0 0 1 18 12c0 3.3-.8 6.3-2.1 8.5M4 13.5C4 9.1 7.6 5.5 12 5.5s8 3.6 8 8c0 1.8-.2 3.5-.6 5M8 12.5a4 4 0 0 1 8 0c0 3.7-.8 7-2.2 9.5M8.3 18.5c-.2-1.5-.3-3.2-.3-5M11.8 9.5a3 3 0 0 0-2.7 1.7"/></>,
    grid: <><rect x="4" y="4" width="6" height="6" rx="1"/><rect x="14" y="4" width="6" height="6" rx="1"/><rect x="4" y="14" width="6" height="6" rx="1"/><rect x="14" y="14" width="6" height="6" rx="1"/></>,
    home: <><path d="m3 11 9-8 9 8"/><path d="M5 10v10h14V10M9 20v-6h6v6"/></>,
    plus: <path d="M12 5v14M5 12h14"/>,
    edit: <><path d="m14 5 5 5M4 20l4.2-1 10-10a2 2 0 0 0-3-3l-10 10L4 20Z"/></>,
    trash: <><path d="M4 7h16M9 7V4h6v3M7 7l1 13h8l1-13M10 11v5M14 11v5"/></>,
    logout: <><path d="M10 5H5v14h5M14 8l4 4-4 4M9 12h9"/></>,
  };
  return <svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">{paths[name]}</svg>;
}

function firstName(name: string) { return name.trim().split(/\s+/)[0] || 'there'; }
function formatDate(value: string) { return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' }).format(new Date(value.endsWith('Z') ? value : `${value}Z`)); }

createRoot(document.getElementById('root')!).render(<App />);
