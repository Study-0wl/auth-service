# auth-service — open items

Known gaps, deliberately left out of the first build. Each links to where it
hooks into the code, so picking one up later doesn't require re-deriving context.

## 1. Device attestation (Play Integrity) on request-otp

**Status:** not implemented — the field was removed entirely rather than kept
as an unenforced placeholder (an unchecked field that looks like a security
control is worse than no field, since it misleads a future reader).

**Why it matters:** without it, `POST /auth/request-otp` can be called
directly (curl/Postman/a script) instead of only from the real Android app.
Rate limiting (see `RateLimiter`) caps *how often* a given phone number can be
hit, but doesn't stop an attacker who rotates through many phone numbers —
device attestation is what would catch that, by rejecting callers that aren't
the genuine app in the first place.

**How it would work:**
1. Android app calls Google's Play Integrity SDK on-device, gets back a
   signed token, sends it up as part of the request.
2. This service calls Google's `decodeIntegrityToken` endpoint server-side
   (a separate Google Cloud project + service account — independent of AWS)
   to verify the token's signature and check its verdicts (app recognized,
   device not rooted/tampered, nonce matches this specific request).
3. Reject with 403 if verdicts don't meet the bar.

**Blocked on:** the Android app isn't sending real tokens yet. Backend
verification alone is meaningless without that half existing — natural
trigger to pick this up is once the Android side starts integrating Play
Integrity.

**Hook point:** `CognitoAuthService.requestOtp()`.

## 2. ~~RateLimiter was in-memory only~~ — done

**Status:** resolved. Runs on DynamoDB (fixed-window atomic conditional
`UpdateItem`), so it survives restarts and works correctly across multiple
instances. TTL (`expiresAt`) handles cleanup — no scheduled eviction job needed.

Local dev: `docker compose up` (repo root) runs DynamoDB Local (port 8000) + a
dynamodb-admin GUI (port 8001) to browse the table directly. Table auto-creates
on startup only when `aws.dynamodb.endpoint-override` is set (see
`DynamoDbTableInitializer`) — never against real AWS; production tables are
provisioned separately (console/IaC), same as the S3 bucket and Cognito pool.

Rate limiting went from a true sliding window (in-memory deque) to a fixed
window (DynamoDB) — slightly less precise (small burst possible right at an
hour boundary), an acceptable trade for "roughly N/hour" abuse prevention.

This item used to also cover `ProfileSessionStore` — that class is gone now,
not just moved to DynamoDB. `complete-profile`'s identity now comes from the
gateway (`X-User-Sub`), not a stored session; see item #5 and README.md's
"Identity for complete-profile" section.

**Hook point:** `RateLimiter.java`, `DynamoDbTableInitializer.java`,
`docker-compose.yml`.

## 3. ~~LoggingUserProfileClient is a stub~~ — done

**Status:** resolved. `HttpUserProfileClient` calls the real User Profile
service's `POST /profiles` over a reactive `WebClient`
(`UserProfileClient.createProfile` returns `Mono<Void>`), authenticated with
an `InternalServiceTokenProvider`-minted client_credentials access token
(cached until just before expiry, see that class).

**Still blocked on:** `auth-pool`'s internal-service App Client (the
client_credentials grant) isn't provisioned in Cognito yet — see
user-profile-service's own `internal.auth.required-scope` TODO. Until it is,
every `POST /profiles` call will 401, since `InternalServiceTokenProvider`
has nowhere real to fetch a token from (`INTERNAL_AUTH_TOKEN_URI` etc. blank).

**Hook point:** `UserProfileClient.java` / `HttpUserProfileClient.java` /
`InternalServiceTokenProvider.java` / `UserProfileServiceProperties.java`,
called from `CognitoAuthService.completeProfile()`.

## 4. refresh-token doesn't support an App Client with a secret

**Status:** works fine for a public client (no secret) — the normal choice
for a mobile app. If a client secret is ever turned on, this specific
endpoint breaks, because Cognito's SECRET_HASH requires the *username*, which
`/auth/refresh-token` never receives (only the opaque refresh token).

**Fix, if ever needed:** have the client also pass the phone number (or
decode it from the ID token client-side) alongside the refresh token, or —
simpler — just don't enable a client secret on this app client.

**Hook point:** `CognitoAuthService.refreshToken()`.

## 5. Kong's local jwt plugin uses a static key, not live JWKS

**Status:** working, but with a known local-dev-only limitation — not something
to "fix" so much as something to swap out before this ever matters for real.

**Why it matters:** `kong/kong.yml`'s `jwt` plugin credential has one of
Cognito's two currently-published RSA public keys pasted in directly (fetched
once from the pool's `.well-known/jwks.json`). Cognito can sign with either of
its two keys and rotates which one is "active" over time. If verification
starts failing for what looks like a valid token, Cognito has likely rotated
to signing with its *other* key — re-fetch the JWKS and swap the PEM (see the
comment in `kong/kong.yml` for the exact steps). This is fine for local dev
(agreed acceptable tradeoff — see chat/design history), never acceptable for
a real deployment.

**Fix, when this goes to production:** use a gateway that does real automatic
JWKS discovery + key rotation instead of a pasted-in static key — AWS API
Gateway's native Cognito authorizer is the natural fit here. Kong *can* do this
too, but only via its `openid-connect` plugin, which is Enterprise-only
(confirmed via Kong's own plugin metadata) — Kong's free `jwt` plugin has no
equivalent.

**Hook point:** `kong/kong.yml`, `docker-compose.yml` (repo root).

## 6. `custom:role` on the Cognito user pool is a dead attribute — don't use it

**Status:** tried, then reverted. `role` briefly lived on the Cognito user
itself: written as a `custom:role` attribute at account creation
(`createPasswordLessUser`, from a `role` field on `RequestOtpRequest`) and
read back at `complete-profile` time. Reverted once it became clear this
breaks role-switching: Cognito identity is 1:1 with a phone/email, so pinning
role to the Cognito user makes it a permanent property of that account, and
there's no way to change it (or have one identifier act as both roles)
without a much bigger redesign (separate Cognito pools per role — considered
and rejected as disproportionate for this stage of the app).

**Where it lives instead:** purely in user-profile-service, as normal mutable
profile fields — `roles` (a list, not a single value: an account can hold
more than one, e.g. both `STUDENT` and `OWNER`, instead of needing a separate
account per role) plus `defaultRole` (which one to render by default).
`complete-profile` only ever collects one role at registration
(`CompleteProfileRequest.role`), sent as a single-element `roles` list with
that same value as `defaultRole` (see `CognitoAuthService.buildCreateProfileRequest`);
gaining an additional role or changing `defaultRole` later is just calling
user-profile-service's existing `PATCH /profiles/me` again, no new endpoint
needed.

**Leftover to be aware of:** the `custom:role` attribute itself is still
defined on the Cognito user pool's schema — Cognito custom attributes can't
be deleted or have their type/mutability changed once added, only added
alongside. It's harmless (nothing reads or writes it anymore) but will show
up in the console indefinitely; don't be surprised by it, and don't resurrect
reading it thinking it's authoritative for anything.

**Hook point:** `CognitoAuthService.createPasswordLessUser()` /
`buildCreateProfileRequest()` (now clean of it), `CompleteProfileRequest.java`.

## 7. No way to safely add/change a phone number or email on an existing account

**Status:** not implemented. The Android app's profile-edit screen intentionally
shows phone/email as locked/view-only (not editable) specifically because of
this gap — see WiseOwl's ProfileDetailsScreen.

**Why it matters:** Cognito's *username* for a user in this pool is literally
whatever identifier (phone or email) they first signed up with (see
`createPasswordLessUser`) — each Cognito user has exactly one identity
attribute set, never both, and there's no linking between them today.
`user-profile-service`'s `phoneNumber`/`email` fields are completely
disconnected from Cognito — `PATCH /profiles/me` only ever writes profile
data, never touches the Cognito user.

If a user who signed up with a phone number were allowed to just type an
email into a profile-edit field and save it, that email would become inert
contact info at best — but if they later tried to *log in* with that email,
`requestOtp` → `userExists` would find no matching Cognito user and
`createPasswordLessUser` would silently create a **second, completely
disconnected account** with a different `userId`/`sub`. Same human, two
unlinked StudyOwl accounts, no merge path. This is what makes it unsafe to
just add a text field for this — the failure mode isn't a validation error,
it's silent account duplication.

**How it would work (the real-world pattern — WhatsApp/Google-style
"verify while already logged in, then link"):**
1. User must already be authenticated (proves ownership of the existing
   account) — this can never be a step available from the sign-in screen.
2. User enters the new phone/email they want to add.
3. Send a fresh OTP to *that new identifier specifically* — a distinct
   verification step from login, reusing the same SMS_OTP/EMAIL_OTP
   mechanism `requestOtp`/`confirmOtp` already use, just scoped to linking
   instead of authenticating.
4. Only once that OTP is confirmed, call Cognito's `AdminUpdateUserAttributes`
   on the caller's *existing* Cognito user (identified by their already-known
   `userId`/`sub` — never by treating the new value as a fresh username) to
   attach the second identifier.
5. Requires the User Pool to have **alias attributes** enabled for
   email/phone_number, so `AdminGetUser`/`AdminInitiateAuth` username lookups
   also resolve by the newly-attached value going forward — without this,
   `userExists`/`requestOtp` would still only recognize the original
   identifier for login purposes even after step 4.
6. Once linked, `user-profile-service`'s `phoneNumber`/`email` fields can be
   updated to match, same `PATCH /profiles/me` call as today.

**Blocked on:** deciding this is worth building (no user demand yet), then
confirming/enabling alias attributes on the Cognito user pool (a console/IaC
change, same category as the pool's OTP challenge config in this class's own
doc comment) before any code changes here.

**Hook point:** `CognitoAuthService.userExists()` / `createPasswordLessUser()`
/ `startUserAuth()` (the alias-attribute-dependent lookups), a new
linking-specific endpoint (not `request-otp`/`confirm-otp`, which are
sign-in-only and unauthenticated today).
