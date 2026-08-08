package com.studyowl.authservice.dto;

import java.util.List;

/**
 * Payload for the internal POST /profiles call to the User Profile service — shaped
 * to match that service's own ProfileRequest exactly (see user-profile-service's
 * dto/ProfileRequest.java and docs/openapi.yaml): userId/roles/defaultRole/
 * phoneNumber/email/firstName/lastName/photoUrl. No separate "identifier" field —
 * userId (the Cognito sub) is the only identifier the profile is keyed on;
 * phoneNumber/email here are just contact attributes, not a stand-in identity.
 * <p>
 * auth-service's own complete-profile only ever collects a single role at
 * registration time (see CompleteProfileRequest) — roles here is always a
 * single-element list built from it, with that same role as defaultRole. A user
 * can hold more than one role, but only ever gains later ones through
 * user-profile-service's own PATCH /profiles/me, not through auth-service.
 */
public record CreateProfileRequest(
        String userId,
        List<Role> roles,
        Role defaultRole,
        String phoneNumber,
        String email,
        String firstName,
        String lastName,
        String photoUrl
) {
}
