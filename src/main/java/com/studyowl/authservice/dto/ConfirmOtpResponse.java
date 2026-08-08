package com.studyowl.authservice.dto;

public record ConfirmOtpResponse(
        boolean isNewUser,
        // No profileToken - complete-profile authenticates the caller via the
        // access token in `tokens` below (through the gateway's X-User-Sub header),
        // not a separate single-use token minted here.
        // Always present now — the native USER_AUTH/SMS_OTP flow issues real tokens
        // the moment the code checks out, for both new and returning users. There's
        // no way to withhold tokens from a new user until they finish complete-profile
        // the way the old password-based hack could; that's a structural property of
        // Cognito's native passwordless flow, not a choice made here.
        Tokens tokens
) {
}
