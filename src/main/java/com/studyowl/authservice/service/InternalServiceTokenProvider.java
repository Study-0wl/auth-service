package com.studyowl.authservice.service;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.studyowl.authservice.config.UserProfileServiceProperties;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

/**
 * Mints (and caches) the internal service-to-service access token HttpUserProfileClient
 * sends as `Authorization: Bearer <token>` on POST /profiles — a real Cognito access
 * token from the client_credentials grant against "auth-pool" (see
 * UserProfileServiceProperties / user-profile-service's InternalAuthUtil, which
 * verifies exactly this token). Cached in memory and refreshed a minute before expiry
 * so a createProfile call doesn't hit the token endpoint on every request — client_credentials
 * tokens for a machine identity are safe to reuse until they actually expire.
 */
@Component
public class InternalServiceTokenProvider {

    private static final long EXPIRY_SAFETY_MARGIN_SECONDS = 60;

    private final WebClient tokenClient;
    private final UserProfileServiceProperties.InternalAuth config;
    private final AtomicReference<CachedToken> cache = new AtomicReference<>();

    public InternalServiceTokenProvider(WebClient.Builder webClientBuilder, UserProfileServiceProperties properties) {
        this.tokenClient = webClientBuilder.build();
        this.config = properties.internalAuth();
    }

    public Mono<String> getAccessToken() {
        CachedToken cached = cache.get();
        if (cached != null && cached.isValid()) {
            return Mono.just(cached.accessToken());
        }
        return fetchToken().doOnNext(cache::set).map(CachedToken::accessToken);
    }

    private Mono<CachedToken> fetchToken() {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "client_credentials");
        form.add("scope", config.scope());

        return tokenClient.post()
                .uri(config.tokenUri())
                .headers(headers -> headers.setBasicAuth(config.clientId(), config.clientSecret()))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData(form))
                .retrieve()
                .bodyToMono(TokenResponse.class)
                .map(response -> new CachedToken(
                        response.accessToken(),
                        Instant.now().plusSeconds(response.expiresIn() - EXPIRY_SAFETY_MARGIN_SECONDS)));
    }

    private record TokenResponse(
            @JsonProperty("access_token") String accessToken,
            @JsonProperty("expires_in") long expiresIn
    ) {
    }

    private record CachedToken(String accessToken, Instant expiresAt) {
        boolean isValid() {
            return Instant.now().isBefore(expiresAt);
        }
    }
}
