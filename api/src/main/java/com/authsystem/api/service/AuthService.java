package com.authsystem.api.service;

import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.authsystem.api.dto.auth.LoginResponse;
import com.authsystem.api.dto.auth.SignupRequest;
import com.authsystem.api.dto.auth.SignupResponse;
import com.authsystem.api.dto.auth.UserInfo;
import com.authsystem.api.entity.User;
import com.authsystem.api.exception.AuthenticationException;

@Service
@Transactional
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    private final UserService userService;
    private final JwtDecoder jwtDecoder;

    @Value("${app.auth.token-expiration:3600}") // Default 1 hour
    private Long tokenExpirationSeconds;

    @Value("${app.auth.auto-create-users:true}")
    private Boolean autoCreateUsers;

    public AuthService(UserService userService, JwtDecoder jwtDecoder) {
        this.userService = userService;
        this.jwtDecoder = jwtDecoder;
    }

    /**
     * Process login with Keycloak token
     */
    public LoginResponse processKeycloakLogin(String accessToken) {
        logger.info("Processing Keycloak login with token");
        try {
            Jwt jwt = jwtDecoder.decode(accessToken);

            String username = jwt.getClaimAsString("preferred_username");
            String email = jwt.getClaimAsString("email");
            List<String> roles = extractRolesFromJwt(jwt);

            User user = findOrCreateUser(username, email);

            userService.validateUserAccountStatus(user);
            userService.updateLastLogin(user.getId());

            UserInfo userInfo = createUserInfoWithRoles(user, roles);
            Long expiresIn = calculateTokenExpiration(jwt);

            return new LoginResponse(
                    accessToken,
                    "Bearer",
                    expiresIn,
                    null, // refresh token placeholder
                    userInfo
            );
        } catch (Exception e) {
            logger.error("Error processing Keycloak login", e);
            throw AuthenticationException.tokenInvalid();
        }
    }

    /**
     * Process user signup
     */
    public SignupResponse processSignup(SignupRequest request) {
        logger.info("Processing signup for username: {}", request.getUsername());

        if (!request.isPasswordMatching()) {
            throw AuthenticationException.invalidRequest("Passwords do not match");
        }

        try {
            // Only use username, email, password, mobile
            User user = userService.createUser(
                    request.getUsername(),
                    request.getEmail(),
                    request.getPassword(),
                    request.getMobileNumber()
            );

            UserInfo userInfo = userService.convertToUserInfo(user);
            return SignupResponse.success(userInfo);
        } catch (AuthenticationException e) {
            logger.warn("Signup failed for {}: {}", request.getUsername(), e.getMessage());
            throw e;
        } catch (Exception e) {
            logger.error("Unexpected error during signup", e);
            throw new RuntimeException("Signup failed. Please try again later.");
        }
    }

    public void logout(String accessToken) {
        try {
            Jwt jwt = jwtDecoder.decode(accessToken);
            String username = jwt.getClaimAsString("preferred_username");
            logger.info("User logged out: {}", username);
        } catch (Exception e) {
            logger.warn("Error processing logout", e);
        }
    }

    public LoginResponse refreshToken(String refreshToken) {
        throw new UnsupportedOperationException("Token refresh not yet implemented");
    }

    public UserInfo getCurrentUserInfo(String accessToken) {
        try {
            Jwt jwt = jwtDecoder.decode(accessToken);
            String username = jwt.getClaimAsString("preferred_username");

            User user = userService.findByUsername(username);
            List<String> roles = extractRolesFromJwt(jwt);

            return createUserInfoWithRoles(user, roles);
        } catch (Exception e) {
            logger.error("Error getting current user info", e);
            throw AuthenticationException.tokenInvalid();
        }
    }

    public UserInfo validateToken(String accessToken) {
        try {
            Jwt jwt = jwtDecoder.decode(accessToken);

            if (jwt.getExpiresAt() != null && jwt.getExpiresAt().isBefore(java.time.Instant.now())) {
                throw AuthenticationException.tokenExpired();
            }

            String username = jwt.getClaimAsString("preferred_username");
            User user = userService.findByUsername(username);
            userService.validateUserAccountStatus(user);

            List<String> roles = extractRolesFromJwt(jwt);
            return createUserInfoWithRoles(user, roles);
        } catch (AuthenticationException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Error validating token", e);
            throw AuthenticationException.tokenInvalid();
        }
    }

    // ---------- Helper methods ----------

    private User findOrCreateUser(String username, String email) {
        try {
            return userService.findByUsername(username);
        } catch (AuthenticationException e) {
            if (autoCreateUsers) {
                logger.info("Auto-creating user: {}", username);
                return userService.createUser(username, email, null, null); // mobile left null if not available
            } else {
                throw AuthenticationException.userNotFound();
            }
        }
    }

    private List<String> extractRolesFromJwt(Jwt jwt) {
        try {
            Map<String, Object> realmAccess = jwt.getClaimAsMap("realm_access");
            if (realmAccess != null && realmAccess.containsKey("roles")) {
                @SuppressWarnings("unchecked")
                List<String> roles = (List<String>) realmAccess.get("roles");
                return roles != null ? roles : List.of("USER");
            }
            return List.of("USER");
        } catch (Exception e) {
            logger.warn("Error extracting roles, defaulting to USER", e);
            return List.of("USER");
        }
    }

    private UserInfo createUserInfoWithRoles(User user, List<String> roles) {
        UserInfo info = userService.convertToUserInfo(user);
        info.setRoles(roles);
        return info;
    }

    private Long calculateTokenExpiration(Jwt jwt) {
        if (jwt.getExpiresAt() != null) {
            long expiresAt = jwt.getExpiresAt().getEpochSecond();
            long now = java.time.Instant.now().getEpochSecond();
            return Math.max(0, expiresAt - now);
        }
        return tokenExpirationSeconds;
    }
}
