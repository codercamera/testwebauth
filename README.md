# Passkey Lab

A small mobile-first WebAuthn test application for Cloudflare Workers and D1. It contains an initial database wizard, first-admin setup, passkey registration and login, password fallback, session management, passkey settings, and an intentionally blank authenticated dashboard.

## Architecture

- React and Vite frontend
- Hono API running on Cloudflare Workers
- Cloudflare D1 database
- `@simplewebauthn` for WebAuthn ceremony generation and verification
- Same-origin frontend and API

The D1 resource and its Worker binding must exist before the app starts. The application wizard creates the tables inside an empty D1 database.

## Initial setup flow

1. The app checks for the `DB` D1 binding.
2. If the binding exists but has no application schema, the setup wizard opens.
3. The operator enters the Worker `SETUP_KEY`, application identity, RP ID, origin, and first administrator.
4. The Worker creates all tables and the administrator in one D1 batch.
5. The administrator registers and verifies the first passkey.
6. Only after successful passkey verification is the installation marked complete and setup locked.

If setup is interrupted after table creation, reopening the application resumes at first-passkey registration.

## Cloudflare preparation

### 1. Install dependencies

```sh
npm install
```

### 2. Create D1

```sh
npx wrangler d1 create testwebauth
```

Copy the returned database ID into `wrangler.jsonc`, replacing `REPLACE_WITH_YOUR_D1_DATABASE_ID`.

### 3. Create the setup secret

Generate a long random value and save it as a Worker secret:

```sh
npx wrangler secret put SETUP_KEY
```

The browser setup wizard requires this value. It prevents the first public visitor from claiming the administrator account.

For local development, copy `.dev.vars.example` to `.dev.vars` and replace its values. `.dev.vars` is ignored by Git.

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
- Passwords use PBKDF2-SHA-256 with a unique salt and 210,000 iterations.
- Session cookies are `HttpOnly`, `Secure`, `SameSite=Lax`, and contain random opaque tokens.
- Only hashed session tokens are stored in D1.
- Cross-origin state-changing API requests are rejected.
- The final passkey cannot be removed until another passkey has been registered.

This is intentionally a focused authentication test bed. Before using it for production accounts, add rate limiting, verified recovery, email ownership verification, operational monitoring, and a formal security review.
