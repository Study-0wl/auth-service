package com.studyowl.authservice.controller;

import com.studyowl.authservice.dto.CompleteProfileRequest;
import com.studyowl.authservice.dto.ConfirmOtpRequest;
import com.studyowl.authservice.dto.ConfirmOtpResponse;
import com.studyowl.authservice.dto.PhotoUploadUrlRequest;
import com.studyowl.authservice.dto.PhotoUploadUrlResponse;
import com.studyowl.authservice.dto.RefreshTokenRequest;
import com.studyowl.authservice.dto.RequestOtpRequest;
import com.studyowl.authservice.dto.RequestOtpResponse;
import com.studyowl.authservice.dto.Tokens;
import com.studyowl.authservice.service.CognitoAuthService;
import com.studyowl.authservice.service.ProfilePhotoService;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/**
 * One controller, thin — every endpoint just validates the request shape (via @Valid)
 * and delegates straight to CognitoAuthService / ProfilePhotoService. All the actual
 * Cognito logic and the reasoning behind it lives there, not here. Mirrors
 * docs/openapi.yaml path-for-path.
 * <p>
 * complete-profile and photoUploadUrl read X-User-Sub, a header this service never
 * validates itself — Kong verifies the caller's Cognito access token and injects this
 * header only after that succeeds (see kong/kong.yml and README.md). That's only safe
 * because auth-service is never reachable except through Kong; if that stops being
 * true, this header stops being trustworthy.
 */
@RestController
@RequestMapping("/auth")
public class AuthController {

    private final CognitoAuthService authService;
    private final ProfilePhotoService photoService;

    public AuthController(CognitoAuthService authService, ProfilePhotoService photoService) {
        this.authService = authService;
        this.photoService = photoService;
    }

    @PostMapping("/request-otp")
    public RequestOtpResponse requestOtp(@Valid @RequestBody RequestOtpRequest request) {
        return authService.requestOtp(request.identifier());
    }

    @PostMapping("/confirm-otp")
    public ConfirmOtpResponse confirmOtp(@Valid @RequestBody ConfirmOtpRequest request) {
        return authService.confirmOtp(request.identifier(), request.otp(), request.session());
    }

    @PostMapping("/complete-profile/photo-upload-url")
    public PhotoUploadUrlResponse photoUploadUrl(
            @RequestHeader("X-User-Sub") String userId,
            @Valid @RequestBody PhotoUploadUrlRequest request
    ) {
        return photoService.createUploadUrl(userId, request.contentType());
    }

    @PostMapping("/complete-profile")
    public Mono<Void> completeProfile(
            @RequestHeader("X-User-Sub") String userId,
            @Valid @RequestBody CompleteProfileRequest request
    ) {
        return authService.completeProfile(userId, request.firstName(), request.lastName(), request.role(), request.photoUrl());
    }

    @PostMapping("/refresh-token")
    public Tokens refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        return authService.refreshToken(request.refreshToken());
    }
}
