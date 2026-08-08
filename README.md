# auth-service

Spring Boot (Java 17) implementation of `docs/openapi.yaml` — phone number + OTP
login/registration, backed by AWS Cognito. Companion to
[../docs/studyowl-auth-flow.md](../docs/studyowl-auth-flow.md).

## The architecture this code uses (and the history behind it)

This service is built on Cognito's **native choice-based `USER_AUTH` flow with
the `SMS_OTP` challenge** — a first-party AWS mechanism for exactly this use
case, no Lambda triggers, and **no passwords anywhere, not even a throwaway
one**.

**Worth knowing:** an earlier version of this service used a workaround —
repurposing `SignUp`/`ForgotPassword` plus a randomly generated, never-shown
password, because that used to be the only way to get SMS-delivered OTP login
out of Cognito without deploying Custom Auth Challenge Lambda triggers. That
workaround was replaced once it turned out AWS added `USER_AUTH`/`SMS_OTP`
specifically to solve this problem natively. If you ever see references to a
`PasswordGenerator` class or `ConfirmForgotPassword`-as-OTP in old commits or
docs, that's what they're from — it's gone now.

**How it works:**

| Step | Call | What happens |
|---|---|---|
| New number only | `AdminCreateUser` (no password, `MessageAction=SUPPRESS`) | Creates the Cognito user; suppresses Cognito's default welcome message since we want our own OTP flow to be the first thing the user sees |
| Both paths | `AdminInitiateAuth(AuthFlow=USER_AUTH, PREFERRED_CHALLENGE=SMS_OTP)` | This is what actually sends the SMS. Returns a `session` token (Cognito's own, opaque) |
| Both paths | `AdminRespondToAuthChallenge(ChallengeName=SMS_OTP, ChallengeResponses={USERNAME, SMS_OTP_CODE}, Session=...)` | Verifies the code, returns real tokens (`AuthenticationResult`) directly |

Because tokens come back the moment the code checks out, `confirm-otp` issues
tokens for **new and returning users alike** — there's no way to withhold
tokens from a new user until `complete-profile` runs, the way the old
password-based version could. `complete-profile` is now purely about
finishing registration (name/photo), not about token issuance — see its
section below.

New-vs-returning is derived from `email_verified`/`phone_number_verified` via
`AdminGetUser`, checked in `isFirstLogin()` — **not** `UserStatus`, despite an
earlier version of this README saying otherwise. A passwordless `AdminCreateUser`
(no password, `MessageAction=SUPPRESS`) gets `UserStatus=CONFIRMED` immediately —
confirmed by testing against a real pool — since there's no temporary password to
force-change and no self-service confirmation code pending, so Cognito has nothing
"unconfirmed" to report. `email_verified`/`phone_number_verified` is the attribute
that actually behaves the way `UserStatus` was expected to: `createPasswordLessUser()`
never sets it, so it starts `false`, and per AWS's passwordless docs, Cognito flips it
to `true` as a side effect of the first successful OTP. Same reason as before: this
check has to run **before** `AdminRespondToAuthChallenge`, since checking after would
always see it already flipped to `true` and could never detect a first login.

## Identity for complete-profile: gateway-verified, not app-verified

`complete-profile` and its `photo-upload-url` step need to know *which* user is
calling — but unlike an earlier version of this service, that's not a separate
`profileToken` anymore. `confirm-otp` already hands back a real Cognito access
token; these two endpoints just expect it as a normal `Authorization: Bearer
<accessToken>` header, like any other authenticated API.

The twist: **this service never parses or verifies that token itself.** It trusts a
`X-User-Sub` header instead, and does nothing to check where that header came from.
That's deliberate, not an oversight — verifying a JWT properly (fetching the
issuer's JWKS, handling key rotation, checking `client_id` since Cognito access
tokens don't carry a standard `aud` claim) is exactly the kind of thing worth doing
once, at the edge, rather than rebuilding into every backend service StudyOwl ends
up with. A gateway does it instead:

- **Locally**: Kong (`kong/kong.yml`, started via the repo-root `docker-compose.yml`,
  proxying on port 8010). Its `jwt` plugin checks the token's signature against one
  of Cognito's own currently-published public keys (fetched once from the pool's
  `.well-known/jwks.json` and pasted into `kong/kong.yml` — not fetched dynamically,
  see the caveat in that file about what to do if Cognito rotates to signing with
  its *other* key and verification starts failing). A `post-function` plugin then
  decodes the now-verified token and sets `X-User-Sub` before forwarding to
  auth-service.
- **Production**: whatever real gateway sits in front of this service (AWS API
  Gateway's native Cognito authorizer is the natural fit) does the equivalent, with
  proper automatic JWKS rotation — something Kong's free tier doesn't do (see
  `kong/kong.yml`'s comments for why).

**This is only safe because auth-service is never reachable except through that
gateway.** If it ever became directly reachable — wrong security group, no network
isolation, a debug port left open — `X-User-Sub` becomes trivially spoofable, since
nothing downstream of the gateway checks it again. Nothing in the app code can
protect against that; it's purely a network-topology guarantee that has to hold
wherever this gets deployed.

## Required Cognito User Pool / App Client configuration

This is different from what an older version of this README described —
these are the settings the native flow actually needs:

- **Feature plan**: User Pool must be on **Essentials or Plus** (not Lite).
  New pools default to Essentials, so this is likely already fine — check
  under **Settings → Feature plans** in the console if unsure.
- **Choice-based sign-in**: under **Sign-in → Options for choice-based
  sign-in**, add **SMS message one-time password**.
- **App Client**: add **`ALLOW_USER_AUTH`** to allowed authentication flows
  (replaces the old `ALLOW_ADMIN_USER_PASSWORD_AUTH` requirement — that flow
  isn't used anymore). Keep `ALLOW_REFRESH_TOKEN_AUTH` enabled for
  `/auth/refresh-token`. No client secret, unless you have a specific reason
  to enable one — a secret can't be kept safe inside a mobile APK anyway. If
  you do enable one, set `COGNITO_CLIENT_SECRET`; the code computes the
  required `SECRET_HASH` automatically wherever Cognito needs it.
- **MFA**: OTP-as-first-factor is incompatible with *required* MFA on the
  pool. Needs MFA set to Off or Optional (normal for a phone-only auth app).
- **Sign-in identifiers**: phone number enabled as a sign-in option, so a
  phone number can be used directly as `Username`.
- **SMS**: an SNS (or Pinpoint) configuration capable of sending SMS is
  attached to the pool, and the AWS account has moved out of SMS sandbox
  (per the "pending" list in the auth-flow doc).
- **IAM**: the credentials this service runs with need `cognito-idp:AdminGetUser`,
  `AdminCreateUser`, `AdminInitiateAuth`, `AdminRespondToAuthChallenge`. Also
  needs `dynamodb:GetItem`/`PutItem`/`UpdateItem`/`DeleteItem` on the two
  tables in **Local dev vs. production DynamoDB** below (not `CreateTable` —
  production tables are provisioned separately, the app only auto-creates
  them locally). Easiest to start with `AmazonCognitoPowerUser` and tighten
  later — a least-privilege example policy (scoped to one user pool ARN) is
  used as the walkthrough example when setting up the dev IAM role.

## Configuration

All config is environment variables (see `src/main/resources/application.yml`
for defaults):

| Variable | Required | Notes |
|---|---|---|
| `AWS_REGION` | yes | e.g. `ap-south-1` |
| `COGNITO_USER_POOL_ID` | yes | |
| `COGNITO_CLIENT_ID` | yes | The App Client ID (not the pool ID) |
| `COGNITO_CLIENT_SECRET` | only if the App Client has a secret | leave unset for a public client |
| `PROFILE_PHOTO_BUCKET` | yes, if using the photo upload step | S3 bucket for profile photos |
| `DYNAMODB_ENDPOINT_OVERRIDE` | local dev only | `http://localhost:8000` to point at DynamoDB Local; leave unset in production |
| `DYNAMODB_RATE_LIMITS_TABLE` | no | defaults to `auth-rate-limits` |
| `USER_PROFILE_SERVICE_BASE_URL` | yes, for complete-profile to actually reach the User Profile service | e.g. `http://localhost:8081`; where `HttpUserProfileClient` sends `POST /profiles` |
| `INTERNAL_AUTH_TOKEN_URI` | yes, for complete-profile to actually reach the User Profile service | `auth-pool`'s OAuth2 token endpoint, e.g. `https://<domain>.auth.<region>.amazoncognito.com/oauth2/token` |
| `INTERNAL_AUTH_CLIENT_ID` / `INTERNAL_AUTH_CLIENT_SECRET` | same as above | the internal-service App Client's credentials (client_credentials grant) in `auth-pool` |
| `INTERNAL_AUTH_SCOPE` | same as above | must match user-profile-service's `internal.auth.required-scope` exactly |

AWS credentials themselves are **not** configured here — the SDK picks them
up from the standard chain (env vars / `~/.aws/credentials` locally, an
instance role in AWS). Never put access keys in `application.yml`. The one
exception is `DynamoDbClient` when `DYNAMODB_ENDPOINT_OVERRIDE` is set — see
"Local dev vs. production DynamoDB" below.

## Local dev vs. production DynamoDB

`RateLimiter` is backed by DynamoDB — one small table with a TTL attribute
(`expiresAt`) so items clean themselves up with no scheduled job needed. (An
earlier version of this service also kept a `ProfileSessionStore` table for
`profileToken` bookkeeping — gone now that identity for complete-profile comes
from the gateway instead; see "Identity for complete-profile" above.)

**Local dev:** the repo-root `docker-compose.yml` runs DynamoDB Local (port 8000)
plus a web GUI, dynamodb-admin (port 8001, `http://localhost:8001`), for browsing
table contents directly — alongside Kong, in the same file.

```bash
docker compose up -d   # from the repo root
```

With `DYNAMODB_ENDPOINT_OVERRIDE=http://localhost:8000` set, the app talks to
that container using dummy credentials (`AwsClientConfig`) and **automatically
creates the table on startup** if it doesn't exist yet (`DynamoDbTableInitializer`)
— no manual table setup step, `docker compose up` + `mvn spring-boot:run` just
works. Data is in-memory in the container and resets on restart, which is fine
here since the table only ever holds short-lived counters anyway.

**Production:** leave `DYNAMODB_ENDPOINT_OVERRIDE` unset. The app then talks
to real regional DynamoDB using the same IAM role as Cognito/S3 — and does
**not** attempt to create the table (`DynamoDbTableInitializer` only runs when
the endpoint override is set). Provision it yourself (console or IaC), same as
the S3 bucket and Cognito pool were set up:

- `auth-rate-limits` — partition key `rateLimitKey` (String), TTL on `expiresAt`
- On-demand (pay-per-request) billing mode is the natural fit at low/sporadic traffic

## Running locally

```bash
# From the repo root — brings up Kong (proxy on :8010, admin API on :8011) and
# DynamoDB Local + dynamodb-admin, all in one compose file.
docker compose up -d

export AWS_REGION=ap-south-1
export COGNITO_USER_POOL_ID=ap-south-1_xxxxxxxxx
export COGNITO_CLIENT_ID=xxxxxxxxxxxxxxxxxxxxxxxxxx
export PROFILE_PHOTO_BUCKET=studyowl-profile-photos
export DYNAMODB_ENDPOINT_OVERRIDE=http://localhost:8000
# plus whatever AWS credentials env vars you use locally, for Cognito/S3

mvn spring-boot:run
```

Talk to the app **through Kong** (`localhost:8010`), not directly on `:8080` —
`complete-profile` and `photo-upload-url` only work via the gateway, since that's
what actually sets `X-User-Sub`. See "Identity for complete-profile" above.

## Walking through a brand-new phone number, end to end

Steps 1-2 hit auth-service directly (`:8080`) — they're unauthenticated by design,
same either way. Steps 3-4 go **through Kong** (`:8010`) instead, since those are
the ones that need `X-User-Sub`, which only Kong sets.

```bash
# 1. Request a code. Creates the Cognito user (no password) if new, then
#    starts the USER_AUTH/SMS_OTP challenge either way — this is what sends the SMS.
curl -X POST localhost:8080/auth/request-otp -H 'content-type: application/json' -d '{
  "identifier": "+919876543210"
}'
# => { "message": "OTP sent", "otpExpirySeconds": 300, "session": "AYABe..." }

# 2. User reads the SMS, submits the code + the session from step 1 unmodified.
curl -X POST localhost:8080/auth/confirm-otp -H 'content-type: application/json' -d '{
  "identifier": "+919876543210",
  "otp": "123456",
  "session": "<from step 1>"
}'
# => { "isNewUser": true, "tokens": { "idToken": "…", "accessToken": "…", "refreshToken": "…", "expiresIn": 3600 } }
# Real tokens are already issued here, even for a new user — store them now.
# accessToken is what steps 3-4 authenticate with.

# 3. (Optional) get a presigned URL, PUT the photo bytes to it directly.
curl -X POST localhost:8010/auth/complete-profile/photo-upload-url \
  -H 'content-type: application/json' \
  -H 'Authorization: Bearer <accessToken from step 2>' \
  -d '{ "contentType": "image/jpeg" }'
# => { "uploadUrl": "https://…", "photoUrl": "https://…", "expiresInSeconds": 300 }
# curl -X PUT "<uploadUrl>" -H 'content-type: image/jpeg' --data-binary @photo.jpg

# 4. Submit registration details — finishes registration, no new tokens (already have them).
curl -X POST localhost:8010/auth/complete-profile \
  -H 'content-type: application/json' \
  -H 'Authorization: Bearer <accessToken from step 2>' \
  -d '{ "firstName": "Asha", "photoUrl": "<from step 3, if used>" }'
# => 200 OK, empty body
```

A returning number skips step 3/4 entirely — `confirm-otp`'s response has
`isNewUser: false`, and the tokens from step 2 are already everything needed
to land in the app.

## Known gaps / what's next

Tracked in [TODO.md](TODO.md), not duplicated here — that's the one place to
check for open work: device attestation, the User Profile service stub, and
the refresh-token client-secret limitation, each with why it matters and
where it hooks into the code.

One simplification not tied to a specific TODO: **timing-equalization on
request-otp is a fixed floor** (`MIN_REQUEST_OTP_MILLIS`), not a
cryptographically rigorous constant-time guarantee — good enough to defeat
casual timing probes, not a formal side-channel guarantee.
