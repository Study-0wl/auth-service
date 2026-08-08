package com.studyowl.authservice.service;

import com.studyowl.authservice.config.UserProfileServiceProperties;
import com.studyowl.authservice.dto.CreateProfileRequest;
import com.studyowl.authservice.dto.ErrorResponse;
import com.studyowl.authservice.exception.ApiException;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

/**
 * Real implementation of UserProfileClient — calls the User Profile service's
 * POST /profiles directly (never through Kong; that route is internal, see
 * ProfileController's class doc there and docs/openapi.yaml's InternalBearerAuth
 * scheme), authenticated with the client_credentials access token
 * InternalServiceTokenProvider mints. Replaces the old LoggingUserProfileClient
 * placeholder now that the User Profile service exists (see TODO.md #3).
 */
@Component
public class HttpUserProfileClient implements UserProfileClient {

    private final WebClient webClient;
    private final InternalServiceTokenProvider tokenProvider;

    public HttpUserProfileClient(
            WebClient.Builder webClientBuilder,
            UserProfileServiceProperties properties,
            InternalServiceTokenProvider tokenProvider
    ) {
        this.webClient = webClientBuilder.baseUrl(properties.baseUrl()).build();
        this.tokenProvider = tokenProvider;
    }

    @Override
    public Mono<Void> createProfile(CreateProfileRequest request) {
        return tokenProvider.getAccessToken()
                .flatMap(token -> webClient.post()
                        .uri("/profiles")
                        .headers(headers -> headers.setBearerAuth(token))
                        .bodyValue(request)
                        .retrieve()
                        .onStatus(HttpStatusCode::isError, HttpUserProfileClient::toApiException)
                        .toBodilessEntity())
                .then();
    }

    // user-profile-service's own error responses are an ErrorResponse {code, message} —
    // surface those directly (same code/message a client would see calling it
    // directly) instead of collapsing everything to a generic upstream failure.
    private static Mono<? extends Throwable> toApiException(ClientResponse response) {
        return response.bodyToMono(ErrorResponse.class)
                .onErrorReturn(new ErrorResponse("UPSTREAM_ERROR", "User Profile service returned " + response.statusCode()))
                .map(error -> new ApiException(
                        response.statusCode() instanceof HttpStatus status ? status : HttpStatus.BAD_GATEWAY,
                        error.code(),
                        error.message()));
    }
}
