package com.studyowl.authservice.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Where and how to reach the User Profile service's internal POST /profiles endpoint
 * (see user-profile-service/docs/openapi.yaml's InternalBearerAuth scheme). That route
 * is never behind Kong — it's called service-to-service, authenticated with a real
 * Cognito access token minted via the client_credentials grant against "auth-pool",
 * a separate machine-to-machine pool with no end users in it (not the pool Kong
 * verifies user tokens against). See HttpUserProfileClient / InternalServiceTokenProvider.
 */
@ConfigurationProperties(prefix = "user-profile-service")
public record UserProfileServiceProperties(
        String baseUrl,
        InternalAuth internalAuth
) {
    public record InternalAuth(
            // auth-pool's OAuth2 token endpoint, e.g.
            // https://<auth-pool-domain>.auth.<region>.amazoncognito.com/oauth2/token
            String tokenUri,
            // The internal-service App Client's id/secret (client_credentials grant) in auth-pool.
            String clientId,
            String clientSecret,
            // Must be one of that App Client's "Allowed OAuth Scopes" — see
            // user-profile-service's internal.auth.required-scope, which must match.
            String scope
    ) {
    }
}
