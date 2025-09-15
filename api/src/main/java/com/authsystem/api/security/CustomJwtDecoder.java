package com.authsystem.api.security;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;

@Component
public class CustomJwtDecoder implements JwtDecoder {

    private static final Logger logger = LoggerFactory.getLogger(CustomJwtDecoder.class);

    private final JwtDecoder delegate;
    private final OAuth2TokenValidator<Jwt> jwtValidator;

    @Value("${keycloak.realm}")
    private String expectedRealm;

    @Value("${keycloak.resource}")
    private String expectedClientId;

    @Value("${app.security.jwt.leeway:60}")
    private long clockSkewLeewaySeconds;

    public CustomJwtDecoder(@Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}") String jwkSetUri) {
        NimbusJwtDecoder nimbusJwtDecoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
        this.delegate = nimbusJwtDecoder;
        this.jwtValidator = createJwtValidator();
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        Jwt jwt = delegate.decode(token);
        OAuth2TokenValidatorResult validation = jwtValidator.validate(jwt);

        if (validation.hasErrors()) {
            String errorMessages = validation.getErrors().stream()
                    .map(OAuth2Error::getDescription)
                    .reduce((a, b) -> a + ", " + b)
                    .orElse("Unknown validation error");

            throw new JwtValidationException("JWT validation failed: " + errorMessages, validation.getErrors());
        }
        return jwt;
    }

    private OAuth2TokenValidator<Jwt> createJwtValidator() {
        return new DelegatingOAuth2TokenValidator<>(
                new JwtTimestampValidator(Duration.ofSeconds(clockSkewLeewaySeconds)),
                new CustomAudienceValidator(),
                new CustomIssuerValidator(),
                new CustomClaimsValidator()
        );
    }

    private class CustomAudienceValidator implements OAuth2TokenValidator<Jwt> {
        @Override
        public OAuth2TokenValidatorResult validate(Jwt jwt) {
            List<String> audiences = jwt.getClaimAsStringList("aud");
            if (audiences != null && audiences.contains(expectedClientId)) {
                return OAuth2TokenValidatorResult.success();
            }
            String azp = jwt.getClaimAsString("azp");
            if (expectedClientId != null && expectedClientId.equals(azp)) {
                return OAuth2TokenValidatorResult.success();
            }
            return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "Invalid JWT audience", null));
        }
    }

    private class CustomIssuerValidator implements OAuth2TokenValidator<Jwt> {
        @Override
        public OAuth2TokenValidatorResult validate(Jwt jwt) {
            String issuer = jwt.getIssuer() != null ? jwt.getIssuer().toString() : null;
            if (issuer != null && expectedRealm != null && issuer.contains("/realms/" + expectedRealm)) {
                return OAuth2TokenValidatorResult.success();
            }
            return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "Invalid JWT issuer", null));
        }
    }

    private class CustomClaimsValidator implements OAuth2TokenValidator<Jwt> {
        @Override
        public OAuth2TokenValidatorResult validate(Jwt jwt) {
            String tokenType = jwt.getClaimAsString("typ");
            if (tokenType != null && !"Bearer".equals(tokenType)) {
                return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "Invalid JWT type", null));
            }
            if (jwt.getSubject() == null || jwt.getSubject().isEmpty()) {
                return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "Missing subject", null));
            }
            Boolean active = jwt.getClaimAsBoolean("active");
            if (active != null && !active) {
                return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "Token inactive", null));
            }
            return OAuth2TokenValidatorResult.success();
        }
    }

    public boolean isTokenNearExpiration(Jwt jwt, Duration threshold) {
        return jwt.getExpiresAt() != null && jwt.getExpiresAt().isBefore(Instant.now().plus(threshold));
    }

    public Duration getTokenRemainingLifetime(Jwt jwt) {
        return jwt.getExpiresAt() != null ? Duration.between(Instant.now(), jwt.getExpiresAt()) : Duration.ZERO;
    }

    public boolean isTokenFormatValid(String token) {
        if (token == null || token.isBlank()) return false;
        String[] parts = token.split("\\.");
        return parts.length == 3;
    }
}
