package com.studyowl.authservice.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record ConfirmOtpRequest(
        @NotBlank
        @Pattern(regexp = "^\\+[1-9]\\d{1,14}$|^[^\\s@]+@[^\\s@]+$")
        String identifier,

        // Cognito doesn't document a fixed code length for SMS_OTP/EMAIL_OTP (their
        // docs' "123456" is just an example value, not a contract) - accept a
        // reasonable digit-only range rather than assume one specific length.
        @NotBlank
        @Pattern(regexp = "^\\d{4,10}$", message = "otp must be 4-10 digits")
        String otp,

        // The session value returned by request-otp — required by Cognito's own
        // USER_AUTH challenge protocol, not something this service generates.
        @NotBlank
        String session
) {
}
