package com.studyowl.authservice.dto;

public record RequestOtpResponse(
        String message,
        int otpExpirySeconds,
        // Cognito's own session token for the USER_AUTH challenge in progress — opaque
        // to us, not stored server-side. The client must send it back unmodified in
        // confirm-otp. This is Cognito's own mechanism, not a custom correlation ID.
        String session
) {
}
