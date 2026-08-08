package com.studyowl.authservice.service;

import com.studyowl.authservice.dto.CreateProfileRequest;
import reactor.core.publisher.Mono;

/**
 * The "User Profile service" is a separate microservice per docs/studyowl-services-list.md
 * (owns name/photo/contact/preferences), not part of this repo. This interface is the
 * wiring point auth-service uses to hand off the profile row after registration —
 * swap LoggingUserProfileClient for a real WebClient-based implementation once that
 * service exists. See TODO.md #3.
 * <p>
 * Reactive (Mono) so a real implementation can call the User Profile service over
 * WebClient without blocking a servlet thread while waiting on that response.
 */
public interface UserProfileClient {
    Mono<Void> createProfile(CreateProfileRequest request);
}
