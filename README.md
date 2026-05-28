# Okta Bruno Collection

Bruno API collections for Okta's OIDC/OAuth and Admin Management APIs, auto-generated from Okta's official OpenAPI specs and curated with hand-built OAuth flows and legacy authentication endpoints.

## Quick start

1. Install [Bruno](https://www.usebruno.com/).
2. Clone this repo to `~/dev/okta-bruno` (or anywhere you like).
3. Install Python deps and generate the collection:

   ```bash
   pip3 install -r requirements.txt
   python3 scripts/generate.py
   ```

4. Open Bruno → File → Open Collection → select `~/dev/okta-bruno/bruno`.
5. Pick the **OIE-Prod** or **OIE-Preview** environment from the dropdown.
6. Edit the environment values and add your `apiKey`, `oauthClientId`, `oauthClientSecret`, etc.

## Collection layout

```
bruno/
├── environments/
│   ├── OIE-Prod.bru
│   └── OIE-Preview.bru
├── _Curated/                 ← hand-built, never overwritten
│   ├── Flows/                ← OAuth/OIDC flow walkthroughs
│   └── LegacyAuthn/          ← /api/v1/authn endpoints
├── OIDC-OAuth/               ← auto-generated from oauth-minimal.yaml
└── Management/               ← auto-generated from management-minimal.yaml
```

## Regenerating after Okta releases new APIs

1. Bump `OKTA_SPEC_VERSION` in `scripts/generate.py`.
2. Run `python3 scripts/generate.py`.
3. The generator wipes and rewrites `bruno/Management/` and `bruno/OIDC-OAuth/`. The `_Curated/` folder is never touched.
4. Inspect changes with `git diff bruno/`.
5. Commit: `git add specs/ bruno/ && git commit -m "Regenerate from Okta spec X.Y.Z"`.

## Variables

**Environment-scoped** (different per OIE-Prod / OIE-Preview):

| Variable | Description |
|---|---|
| `orgUrl` | Your Okta org URL, e.g. `https://acme.okta.com` |
| `apiKey` | SSWS API token |
| `oauthClientId` | OAuth app client ID |
| `oauthClientSecret` | OAuth app client secret |
| `oauthRedirectUri` | Callback URI for Auth Code flow |
| `testUsername` | User for ROPC / authn flow testing |
| `testPassword` | Password for ROPC / authn flow testing |

**Collection-scoped:**

| Variable | Description |
|---|---|
| `defaultAuthServerId` | `default` — the built-in authorization server |
| `bearerToken` | Populated at runtime by `_Curated/Flows/09-Get-Okta-API-token/` |

**Path placeholders** are written as raw `{{userId}}`, `{{groupId}}`, `{{appId}}`, etc. directly in request URLs. Set them inline per testing session — they are not pre-declared at the collection level.

## Authentication

- **Default:** every Management API request uses `Authorization: SSWS {{apiKey}}`.
- **OAuth alternative:** run `_Curated/Flows/09-Get-Okta-API-token/` first to populate the `bearerToken` variable, then change the `Authorization` header on any request to `Bearer {{bearerToken}}`.
- **OIDC/OAuth requests:** use whatever security scheme each endpoint requires per the spec (basic auth, bearer, or unauthenticated).

## Sources

Auto-generated content comes from:

- `github.com/okta/okta-management-openapi-spec` → `dist/current/management-minimal.yaml`
- `github.com/okta/okta-management-openapi-spec` → `dist/current/oauth-minimal.yaml`

Pinned spec snapshots are committed to `specs/` so `git log` shows the full history of Okta API changes.

## Hand-curated content

The `_Curated/` folder contains:

- **`Flows/`** — 9 walkthrough folders for OAuth/OIDC flows (Authorization Code + PKCE, Client Credentials, ROPC, Refresh Token, Device Authorization, CIBA, Token Introspection, Token Revocation, plus a "Get Okta API token" helper).
- **`LegacyAuthn/`** — `/api/v1/authn` endpoints not in the OpenAPI spec (primary auth, MFA challenges, recovery, unlock, etc.).

These are hand-built and persist across regenerations. Add your own custom test scenarios here — they are safe from `python3 scripts/generate.py`.
