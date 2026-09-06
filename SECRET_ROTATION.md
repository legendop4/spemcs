# Credential rotation required

Every credential listed here was committed to this repository's git history and must be treated as
**public**. Untracking the files that carried them (done — see below) stops new copies being added;
it does **not** remove the values already in history. Until each is rotated at its source, anyone
with a clone of this repository holds a working credential.

No value is reproduced in this document. Each entry names the variable and where to change it.

## Must be rotated, in this order

Ordered by what an attacker gets, most severe first.

### 1. `DATABASE_URL` — PostgreSQL (Neon) role password

Read/write access to every exam, session, device, alert and audit record.

Rotate in the Neon console (reset the role's password, or create a new role and drop the old one),
then set the new connection string in the deployment's secret store and in the local untracked
`backend/.env`. Nothing else needs changing: no other component holds a copy.

Rotating this **invalidates nothing** — sessions, device tokens and signed policies are unaffected.

### 2. `SECRET_KEY` — operator JWT signing key (HS256)

Knowing it lets anyone mint a token for any account, including an administrator, without touching
the login endpoint. There is no revocation list and no `jti` check, so a forged token is
indistinguishable from a real one and cannot be recalled.

Generate a replacement:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

**Effect on live users:** every existing operator token stops verifying immediately, so every
dashboard session must log in again — including the dashboard WebSocket, which will close 4401 and
deliberately not reconnect. Rotate between exams, not during one.

The committed value is also shorter than the 32-character minimum in `backend/app/config.py`, so a
production start already refuses it regardless of the history exposure.

### 3. `DEVICE_TOKEN_SECRET` — device enrolment token HMAC key

**This one was never configured on this deployment at all**, so the backend has been running on the
placeholder default that is committed in `backend/app/config.py`. That value is public, which means
device tokens have been forgeable by anyone reading this repository: forge a token for any
`hardware_uuid` and the agent API accepts you as that workstation.

Generate a replacement the same way as `SECRET_KEY`.

**Effect on live endpoints:** every enrolled agent's stored device token stops verifying and each
machine must re-enrol (which requires `ENROLLMENT_BOOTSTRAP_KEY`, below). Plan this as a fleet
operation, not a config tweak.

### 4. `ENROLLMENT_BOOTSTRAP_KEY` — one-time device registration gate

Also never configured on this deployment, so it too has been running on the committed placeholder.
Knowing it lets anyone register an arbitrary device and be issued a valid device token.

Generate a replacement the same way. It is presented once per machine at enrolment, so rotating it
does not disturb already-enrolled endpoints — but the new value has to reach whatever provisions
them (`config.json` `enrollmentKey`, or the `SPEMCS_ENROLLMENT_KEY` environment variable read by
`EnrollmentKeyProvider`).

## Explicitly NOT on this list

**The RSA policy-signing keyring** (`SIGNING_KEY_DIR`, default `backend/secrets/signing_keys/`).
It is a different kind of secret with a different lifecycle: it is generated once on first use,
never committed, and covered by `.gitignore` (`*.pem`, `secrets/`, `**/secrets/signing_keys/`).
Nothing above requires touching it, and it should not be rotated as part of this exercise —
endpoints verify a distributed policy against the key id recorded inside it, so rotating the
signing key invalidates every already-distributed policy and surfaces as exams that will not start.
Rotate it only through `POST /api/policies/signing-key/rotate`, which supersedes rather than
deletes, so previously signed policies stay verifiable.

On Windows the POSIX file mode the agent sets on the private key directory is **advisory only**.
Restrict that directory with NTFS ACLs; file mode alone does not protect it.

**`BACKEND_HOST` / `BACKEND_PORT`.** Not credentials. `frontend/.env.txt` contained only these two
values, so — contrary to the earlier audit note — no frontend credential was ever exposed.

## What was changed in the repository

- `backend/.env.txt` — **untracked** (`git rm --cached`, working copy kept). Carried `DATABASE_URL`
  and `SECRET_KEY`.
- `frontend/.env.txt` — **untracked** the same way, for consistency with the `.env.txt` rule in
  `.gitignore`. Carried no credentials.
- `.gitignore` already ignores `.env`, `.env.txt`, `*.pem`, `*.key`, `secrets/` and
  `**/secrets/signing_keys/`, so neither file can be re-added by accident.
- `backend/.env.example` documents every variable, including `SPEMCS_ENV`, with placeholders only.
- `backend/app/config.py` refuses to start on a missing, placeholder or too-short shared secret
  unless `SPEMCS_ENV` names a non-production environment. This is why items 3 and 4 above can no
  longer go unnoticed: a production deployment on either default now fails to boot with a message
  naming the variable.

**Git history was not rewritten.** Purging these values from history requires a force push and a
re-clone by every consumer; it is the repository owner's decision, and it is not a substitute for
rotation — a credential that has been public is public whether or not the commit still shows it.
