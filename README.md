# Passkey Lab

A small mobile-first authentication test application for Cloudflare Workers and D1. It contains an initial database wizard, first-admin setup, Google sign-in, optional passkey registration and login, password fallback, session management, security settings, and an intentionally blank authenticated dashboard.

## Architecture

- React and Vite frontend
- Hono API running on Cloudflare Workers
- Cloudflare D1 database
- `@simplewebauthn` for WebAuthn ceremony generation and verification
- Google OpenID Connect using Authorization Code with PKCE
- Same-origin frontend and API

The D1 resource and its Worker binding must exist before the app starts. The application wizard creates the tables inside an empty D1 database.

## Initial setup flow

1. The app checks for the `DB` D1 binding.
2. If the binding exists but has no application schema, the setup wizard opens.
3. The operator enters the Worker `SETUP_KEY`, application identity, RP ID, origin, and first administrator.
4. The Worker creates all tables and the administrator in one D1 batch.
5. Setup is marked complete and the administrator is signed in with a secure session.
6. Passkey registration is optional and available later under **Security → Passkeys**.

If a database was created by an older version that stopped at mandatory passkey registration, the wizard offers a protected “Finish without passkey” recovery step.

## Cloudflare preparation

### 1. Install dependencies

```sh
npm install
```

### 2. Provision D1

The Wrangler configuration declares a D1 binding named `DB` without a fixed database ID. On the first Cloudflare deployment, Wrangler automatically provisions the D1 database and attaches it to the Worker. Its generated database ID is available in the Cloudflare dashboard after deployment and does not need to be committed to GitHub.

If you want to use an existing D1 database instead, replace the binding-only entry in `wrangler.jsonc` with its `database_name` and `database_id`.

### 3. Create the setup secret in Cloudflare

After the first deployment, open the Cloudflare dashboard:

1. Go to **Workers & Pages** and select **testwebauth**.
2. Open **Settings**.
3. Open **Variables and Secrets**.
4. Select **Add**.
5. Set the name to `SETUP_KEY`.
6. Choose **Secret** (encrypted), not plain-text variable.
7. Enter a long random value and save/deploy the change.

The browser setup wizard asks for this same value. It prevents the first public visitor from claiming the administrator account. Never add the real value to GitHub, `wrangler.jsonc`, or frontend code.

The CLI alternative is:

```sh
npx wrangler secret put SETUP_KEY
```

For local development, copy `.dev.vars.example` to `.dev.vars` and replace its value. `.dev.vars` is ignored by Git.

### 4. Choose the hostname before registering passkeys

Configure the final Worker custom domain before creating long-lived passkeys. During setup:

- **RP ID** is the hostname only, such as `passkeys.example.com`.
- **Expected origin** is the exact origin, such as `https://passkeys.example.com`.

Passkeys registered against a temporary `workers.dev` hostname will not automatically move to a different RP ID.

### 5. Deploy

```sh
npm run deploy
```

Open the deployment URL and complete the wizard. No manual SQL migration is required for the first installation.

## Google sign-in

Google sign-in is optional. The Google button stays hidden until both Worker values below are configured.

### 1. Create a Google OAuth client

In Google Cloud Console, create an OAuth 2.0 client with application type **Web application**. Add this exact authorized redirect URI for the default Worker hostname:

```text
https://testwebauth.coder-camera.workers.dev/api/auth/google/callback
```

If you use a custom domain, add its equivalent callback URI as well, for example `https://passkeys.example.com/api/auth/google/callback`. The URI must exactly match the hostname used to open the application.

### 2. Add Cloudflare variables and secrets

Under **Workers & Pages → testwebauth → Settings → Variables and Secrets**, add:

| Type | Name | Value |
| --- | --- | --- |
| Text | `GOOGLE_CLIENT_ID` | The OAuth web client ID from Google |
| Secret | `GOOGLE_CLIENT_SECRET` | The OAuth web client secret from Google |

Deploy the variable changes. The CLI alternatives are:

```sh
npx wrangler secret put GOOGLE_CLIENT_SECRET
```

Add `GOOGLE_CLIENT_ID` as a Worker text variable in the Cloudflare dashboard. For local development, place both values in `.dev.vars`.

**Continue with Google** signs in an existing account and stores Google's stable account ID on first use. **Sign up with Google** creates a new application account with the `user` role from Google's verified email and profile name, then signs the user in. The setup administrator remains the only automatically created `admin`. A signed-in user can connect or disconnect Google under **Security**. Google cannot be disconnected if it is the user's only sign-in method.

Existing installations are upgraded automatically when the application starts; no manual D1 migration is required.

## Local development

```sh
npm run dev
```

Wrangler creates a local D1 database. WebAuthn permits `localhost` for development. Use the local hostname as the RP ID and the exact local origin shown by Wrangler.

## Verification

```sh
npm run typecheck
npm run build
npx wrangler deploy --dry-run --outdir .worker-dist
```

## Security choices in this test application

- Setup requires a Cloudflare Worker secret.
- WebAuthn challenges expire after five minutes and are single-use.
- User verification is required for passkey registration and login.
- The server verifies the expected RP ID and exact origin.
- Passwords use PBKDF2-SHA-256 with a unique salt and the Cloudflare Workers maximum of 100,000 iterations.
- Session cookies are `HttpOnly`, `Secure`, `SameSite=Lax`, and contain random opaque tokens.
- Only hashed session tokens are stored in D1.
- Cross-origin state-changing API requests are rejected.
- Google sign-in validates OAuth state, PKCE, nonce, the ID-token signature, issuer, audience, and verified email; Google access and refresh tokens are not stored.
- The final passkey cannot be removed until another passkey has been registered.

This is intentionally a focused authentication test bed. Before using it for production accounts, add rate limiting, verified recovery, email ownership verification, operational monitoring, and a formal security review.
