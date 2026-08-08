package com.studyowl.authservice.service;

import com.studyowl.authservice.config.CognitoProperties;
import com.studyowl.authservice.config.OtpProperties;
import com.studyowl.authservice.dto.ConfirmOtpResponse;
import com.studyowl.authservice.dto.CreateProfileRequest;
import com.studyowl.authservice.dto.RequestOtpResponse;
import com.studyowl.authservice.dto.Role;
import com.studyowl.authservice.dto.Tokens;
import com.studyowl.authservice.exception.ApiException;
import com.studyowl.authservice.util.SecretHashUtil;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminCreateUserRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminGetUserRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminGetUserResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminInitiateAuthRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminInitiateAuthResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminRespondToAuthChallengeRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminRespondToAuthChallengeResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AttributeType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AuthFlowType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AuthenticationResultType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ChallengeNameType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.MessageActionType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.UserNotFoundException;

/**
 * Core auth logic, built on Cognito's native choice-based USER_AUTH flow, with either
 * the SMS_OTP or EMAIL_OTP challenge depending on whether the caller signs in with a
 * phone number or an email address — no Lambda triggers, and (unlike an earlier version
 * of this class) no throwaway passwords either. This replaced a SignUp/ForgotPassword-
 * repurposing hack once it turned out AWS added a first-party passwordless
 * mechanism that does exactly this job. See README.md for the full history and
 * the Cognito User Pool / App Client configuration this requires
 * (ALLOW_USER_AUTH, SMS_OTP + EMAIL_OTP added to choice-based sign-in, Essentials+ feature
 * plan, Amazon SES configured for EMAIL_OTP specifically).
 */
@Service
public class CognitoAuthService {

    /**
     * request-otp must look and take the same amount of time whether the identifier
     * is new or already registered — otherwise a faster/slower response is itself a
     * signal an attacker can use to enumerate registered accounts. This is a floor on
     * the response time, not a ceiling: real AWS calls may naturally take longer.
     */
    private static final long MIN_REQUEST_OTP_MILLIS = 800;

    private final CognitoIdentityProviderClient cognitoClient;
    private final CognitoProperties cognitoProperties;
    private final OtpProperties otpProperties;
    private final RateLimiter rateLimiter;
    private final UserProfileClient userProfileClient;

    public CognitoAuthService(
            CognitoIdentityProviderClient cognitoClient,
            CognitoProperties cognitoProperties,
            OtpProperties otpProperties,
            RateLimiter rateLimiter,
            UserProfileClient userProfileClient
    ) {
        this.cognitoClient = cognitoClient;
        this.cognitoProperties = cognitoProperties;
        this.otpProperties = otpProperties;
        this.rateLimiter = rateLimiter;
        this.userProfileClient = userProfileClient;
    }

    // ---------------------------------------------------------------- request-otp

    public RequestOtpResponse requestOtp(String identifier) {
        long start = System.currentTimeMillis();

        // Step 1: rate limit, per identifier, before anything else (including the
        // Cognito lookup) — an attacker retrying the same identifier shouldn't get to
        // burn API calls just because the limit check happens after the lookup.
        if (!rateLimiter.tryConsume("identifier:" + identifier, otpProperties.rateLimit().maxRequestsPerPhonePerHour())) {
            throw new ApiException(HttpStatus.TOO_MANY_REQUESTS, "RATE_LIMITED",
                    "Too many OTP requests for this account", 3600);
        }

        // Step 2: does this identifier already have a Cognito user? This lookup uses
        // AdminGetUser, which requires AWS credentials on the backend — it is NOT
        // exposed to the client directly, which is exactly what prevents phone
        // number / email enumeration (see class docs on docs/openapi.yaml).
        if (!userExists(identifier)) {
            createPasswordLessUser(identifier);
        }

        // Step 3: this is what actually triggers the SMS/email send, for new and
        // returning users alike — same call either way, which is part of why this
        // doesn't leak new-vs-existing (see class docs).
        String session = startUserAuth(identifier);

        // Step 4: pad the response time so both branches above look identical from
        // the outside, regardless of which one actually ran.
        long elapsed = System.currentTimeMillis() - start;
        if (elapsed < MIN_REQUEST_OTP_MILLIS) {
            sleepQuietly(MIN_REQUEST_OTP_MILLIS - elapsed);
        }

        return new RequestOtpResponse("OTP sent", otpProperties.expirySeconds(), session);
    }

    /**
     * Cognito's own SignUp API auto-detects email vs. phone number from the username
     * string in exactly this way (see AWS docs on username attributes) — mirrored here
     * since AdminCreateUser/AdminInitiateAuth need to know which attribute and which
     * OTP challenge type to use. Phone numbers are validated E.164 (RequestOtpRequest /
     * ConfirmOtpRequest), which never contains '@', so this is unambiguous.
     */
    private boolean isEmail(String identifier) {
        return identifier.contains("@");
    }

    private boolean userExists(String identifier) {
        try {
            AdminGetUserRequest request = AdminGetUserRequest.builder()
                    .userPoolId(cognitoProperties.userPoolId())
                    .username(identifier)
                    .build();
            cognitoClient.adminGetUser(request);
            return true;
        } catch (UserNotFoundException e) {
            return false;
        }
    }

    /**
     * Creates the Cognito user with no password at all — AdminCreateUser's password
     * parameter is optional, and the whole point of this migration was to stop
     * generating throwaway passwords nobody needed. MessageAction=SUPPRESS stops
     * Cognito sending its own default "welcome" message; startUserAuth() right after
     * this is what actually sends the SMS/email OTP, same as it does for a returning user.
     * No *_verified attribute is set here — that's deliberate: the OTP challenge itself
     * is the verification event (a correct code is what flips it), not something this
     * service should assert up front.
     */
    private void createPasswordLessUser(String identifier) {
        String attributeName = isEmail(identifier) ? "email" : "phone_number";
        AdminCreateUserRequest.Builder builder = AdminCreateUserRequest.builder()
                .userPoolId(cognitoProperties.userPoolId())
                .username(identifier)
                .userAttributes(AttributeType.builder().name(attributeName).value(identifier).build())
                .messageAction(MessageActionType.SUPPRESS);

        cognitoClient.adminCreateUser(builder.build());
    }

    /** Starts (or resumes) the USER_AUTH choice-based flow, requesting SMS_OTP or EMAIL_OTP as appropriate. */
    private String startUserAuth(String identifier) {
        Map<String, String> authParameters = new HashMap<>();
        authParameters.put("USERNAME", identifier);
        authParameters.put("PREFERRED_CHALLENGE", isEmail(identifier) ? "EMAIL_OTP" : "SMS_OTP");
        applySecretHash(authParameters, identifier);

        AdminInitiateAuthRequest request = AdminInitiateAuthRequest.builder()
                .userPoolId(cognitoProperties.userPoolId())
                .clientId(cognitoProperties.clientId())
                .authFlow(AuthFlowType.USER_AUTH)
                .authParameters(authParameters)
                .build();

        AdminInitiateAuthResponse response = cognitoClient.adminInitiateAuth(request);
        return response.session();
    }

    // ---------------------------------------------------------------- confirm-otp

    public ConfirmOtpResponse confirmOtp(String identifier, String otp, String session) {
        // Must check this BEFORE responding to the challenge below — same reason as
        // the UserStatus approach this replaced (see isFirstLogin's own comment for
        // why UserStatus itself turned out not to work here).
        boolean isNewUser = isFirstLogin(identifier);
        boolean isEmail = isEmail(identifier);

        Map<String, String> challengeResponses = new HashMap<>();
        challengeResponses.put("USERNAME", identifier);
        challengeResponses.put(isEmail ? "EMAIL_OTP_CODE" : "SMS_OTP_CODE", otp);
        applySecretHash(challengeResponses, identifier);

        AdminRespondToAuthChallengeRequest request = AdminRespondToAuthChallengeRequest.builder()
                .userPoolId(cognitoProperties.userPoolId())
                .clientId(cognitoProperties.clientId())
                .challengeName(isEmail ? ChallengeNameType.EMAIL_OTP : ChallengeNameType.SMS_OTP)
                .challengeResponses(challengeResponses)
                .session(session)
                .build();

        // Throws CodeMismatchException / ExpiredCodeException on a bad code — handled
        // by GlobalExceptionHandler, mapped to 400 INVALID_OTP / OTP_EXPIRED.
        AdminRespondToAuthChallengeResponse response = cognitoClient.adminRespondToAuthChallenge(request);
        Tokens tokens = toTokens(response.authenticationResult());

        return new ConfirmOtpResponse(isNewUser, tokens);
    }

    /**
     * UserStatus doesn't work for this: a passwordless AdminCreateUser has no temporary
     * password to force-change and no self-service confirmation code pending (MessageAction
     * is SUPPRESS, not a real SignUp), so Cognito gives it UserStatus=CONFIRMED immediately
     * — there's nothing "unconfirmed" about it from Cognito's point of view. Confirmed by
     * testing against a real pool; AWS's own AdminCreateUser docs don't state this outcome.
     * <p>
     * email_verified/phone_number_verified is the right signal instead: createPasswordLessUser
     * never sets it, so it starts false, and AWS's passwordless docs confirm Cognito flips it
     * to true as a side effect of the first successful OTP — same "flips on success, must
     * check before responding to the challenge" property UserStatus was supposed to have.
     */
    private boolean isFirstLogin(String identifier) {
        try {
            AdminGetUserResponse response = cognitoClient.adminGetUser(AdminGetUserRequest.builder()
                    .userPoolId(cognitoProperties.userPoolId())
                    .username(identifier)
                    .build());
            String verifiedAttribute = isEmail(identifier) ? "email_verified" : "phone_number_verified";
            return response.userAttributes().stream()
                    .filter(a -> verifiedAttribute.equals(a.name()))
                    .map(AttributeType::value)
                    .findFirst()
                    .map(value -> !Boolean.parseBoolean(value))
                    .orElse(true);
        } catch (UserNotFoundException e) {
            // Nothing pending to confirm for this identifier. Same generic error as a
            // wrong code, not a 404, so this can't be used to probe for registered accounts.
            throw new ApiException(HttpStatus.BAD_REQUEST, "INVALID_OTP", "Incorrect code");
        }
    }

    // ---------------------------------------------------------------- complete-profile

    /**
     * No tokens to mint here anymore — confirm-otp already issued real tokens for new
     * users too (see ConfirmOtpResponse). No session/token to consume either: userId
     * is already a verified identity by the time this runs (Kong put it there after
     * checking the caller's access token — see AuthController's class doc). This just
     * finishes registration: hand the profile details off to the User Profile service
     * (once it exists — currently LoggingUserProfileClient).
     * <p>
     * role is just forwarded into CreateProfileRequest, not read from or written to
     * Cognito (see TODO.md #6 for why that was tried and reverted) — it's purely a
     * user-profile-service field from here on, and can be changed later via that
     * service's own PATCH /profiles/me, no re-registration needed.
     * <p>
     * Mono.fromCallable defers the (blocking) Cognito lookup until something subscribes,
     * rather than running it eagerly on the calling thread — same place AuthController's
     * Mono chain resolves it today, but this keeps the method composable if a caller
     * ever wants to run it elsewhere (e.g. off the servlet thread via subscribeOn).
     */
    public Mono<Void> completeProfile(String userId, String firstName, String lastName, Role role, String photoUrl) {
        return Mono.fromCallable(() -> buildCreateProfileRequest(userId, firstName, lastName, role, photoUrl))
                .flatMap(userProfileClient::createProfile);
    }

    /**
     * Works because sub and the pool's real internal username are the same value for
     * this pool's "username attributes" mode (see the chat discussion on why the
     * access token's username claim equals sub) — so AdminGetUser accepts userId
     * directly as Username, same as it accepts a phone number or email elsewhere.
     * <p>
     * No separate "identifier" concept here: userId is the only thing the profile is
     * keyed on. The email/phone_number attribute fetched below is just contact info
     * for the request body, split into CreateProfileRequest's phoneNumber/email fields
     * (mirrors the User Profile service's own ProfileRequest shape).
     */
    private CreateProfileRequest buildCreateProfileRequest(String userId, String firstName, String lastName, Role role, String photoUrl) {
        AdminGetUserResponse response = cognitoClient.adminGetUser(AdminGetUserRequest.builder()
                .userPoolId(cognitoProperties.userPoolId())
                .username(userId)
                .build());
        AttributeType contact = response.userAttributes().stream()
                .filter(a -> "email".equals(a.name()) || "phone_number".equals(a.name()))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Cognito user has no email or phone_number attribute: " + userId));

        boolean isEmailAttribute = "email".equals(contact.name());
        return new CreateProfileRequest(
                userId,
                List.of(role),
                role,
                isEmailAttribute ? null : contact.value(),
                isEmailAttribute ? contact.value() : null,
                firstName,
                lastName,
                photoUrl
        );
    }

    // ---------------------------------------------------------------- refresh-token

    public Tokens refreshToken(String refreshToken) {
        Map<String, String> authParameters = new HashMap<>();
        authParameters.put("REFRESH_TOKEN", refreshToken);

        AdminInitiateAuthRequest request = AdminInitiateAuthRequest.builder()
                .userPoolId(cognitoProperties.userPoolId())
                .clientId(cognitoProperties.clientId())
                .authFlow(AuthFlowType.REFRESH_TOKEN_AUTH)
                .authParameters(authParameters)
                .build();

        // Throws NotAuthorizedException if the refresh token is expired/revoked —
        // handled by GlobalExceptionHandler, mapped to 401 per docs/openapi.yaml.
        AdminInitiateAuthResponse response = cognitoClient.adminInitiateAuth(request);
        AuthenticationResultType result = response.authenticationResult();

        // If Refresh Token Rotation is enabled on the App Client, Cognito issues a NEW
        // refresh token on every call here — the client must start using that one
        // going forward, or its session will die at the *original* token's expiry
        // instead of getting extended. If rotation is off, Cognito returns null here
        // and we fall back to re-issuing the same refresh token the client already has.
        String nextRefreshToken = result.refreshToken() != null ? result.refreshToken() : refreshToken;
        return new Tokens(result.idToken(), result.accessToken(), nextRefreshToken, result.expiresIn());
    }

    // ---------------------------------------------------------------- shared helpers

    private Tokens toTokens(AuthenticationResultType result) {
        return new Tokens(result.idToken(), result.accessToken(), result.refreshToken(), result.expiresIn());
    }

    private void applySecretHash(Map<String, String> parameters, String username) {
        if (cognitoProperties.hasClientSecret()) {
            parameters.put("SECRET_HASH", SecretHashUtil.calculate(username, cognitoProperties.clientId(), cognitoProperties.clientSecret()));
        }
    }

    private void sleepQuietly(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
