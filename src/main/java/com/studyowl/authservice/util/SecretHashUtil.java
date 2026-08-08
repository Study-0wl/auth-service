package com.studyowl.authservice.util;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Cognito requires a SECRET_HASH parameter on every API call (SignUp, InitiateAuth,
 * ForgotPassword, ...) IF AND ONLY IF the App Client has "Generate client secret"
 * enabled. Most mobile-app clients are created without a secret (a secret can't be
 * kept safe inside an APK anyway), in which case this class is never called —
 * see CognitoAuthService, which only computes it when a secret is configured.
 *
 * Formula per AWS docs: Base64(HMAC-SHA256(key = client secret, message = username + clientId))
 */
public final class SecretHashUtil {

    private SecretHashUtil() {
    }

    public static String calculate(String username, String clientId, String clientSecret) {
        try {
            String message = username + clientId;
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(clientSecret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] rawHmac = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(rawHmac);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to compute Cognito SECRET_HASH", e);
        }
    }
}
