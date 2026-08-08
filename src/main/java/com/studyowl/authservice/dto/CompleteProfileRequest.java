package com.studyowl.authservice.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

// No profileToken - the caller's identity (Cognito sub) comes from the X-User-Sub
// header, trusted because it's injected by Kong only after verifying the caller's
// access token (see kong/kong.yml). See AuthController/README.md for the full story.
//
// role lives purely in user-profile-service from here on - this just sets its
// initial value at profile creation (defaults to STUDENT there if ever omitted).
// It's NOT fixed for the life of the account: user-profile-service's PATCH
// /profiles/me already lets a user switch it themselves later, no approval step
// (see that service's ProfileController). Deliberately not stored on the Cognito
// user (see TODO.md #6) - Cognito identity is 1:1 with a phone/email, so a mutable
// per-account attribute like "current role" doesn't belong there.
public record CompleteProfileRequest(
        @NotBlank
        String firstName,

        @NotBlank
        String lastName,

        @NotNull
        Role role,

        // Optional. The photoUrl returned by /auth/complete-profile/photo-upload-url,
        // after the client has actually uploaded the file to that presigned URL.
        String photoUrl
) {
}
