package com.authsystem.api.security;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

@Component
public class SecurityUtils {
    
    private static final Logger logger = LoggerFactory.getLogger(SecurityUtils.class);
    
    /**
     * Get current authentication from security context
     */
    public static Optional<Authentication> getCurrentAuthentication() {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication != null && authentication.isAuthenticated()) {
                return Optional.of(authentication);
            }
        } catch (Exception e) {
            logger.debug("Error getting current authentication", e);
        }
        return Optional.empty();
    }
    
    /**
     * Get current JWT token from security context
     */
    public static Optional<Jwt> getCurrentJwt() {
        try {
            Optional<Authentication> auth = getCurrentAuthentication();
            if (auth.isPresent() && auth.get() instanceof JwtAuthenticationToken) {
                JwtAuthenticationToken jwtAuth = (JwtAuthenticationToken) auth.get();
                return Optional.of(jwtAuth.getToken());
            }
        } catch (Exception e) {
            logger.debug("Error getting current JWT", e);
        }
        return Optional.empty();
    }
    
    /**
     * Get current username from security context
     */
    public static Optional<String> getCurrentUsername() {
        try {
            Optional<Authentication> auth = getCurrentAuthentication();
            if (auth.isPresent()) {
                String username = auth.get().getName();
                return Optional.ofNullable(username);
            }
        } catch (Exception e) {
            logger.debug("Error getting current username", e);
        }
        return Optional.empty();
    }
    
    /**
     * Get current user ID from JWT token
     */
    public static Optional<String> getCurrentUserId() {
        try {
            Optional<Jwt> jwt = getCurrentJwt();
            if (jwt.isPresent()) {
                String userId = jwt.get().getSubject();
                return Optional.ofNullable(userId);
            }
        } catch (Exception e) {
            logger.debug("Error getting current user ID", e);
        }
        return Optional.empty();
    }
    
    /**
     * Get current user email from JWT token
     */
    public static Optional<String> getCurrentUserEmail() {
        try {
            Optional<Jwt> jwt = getCurrentJwt();
            if (jwt.isPresent()) {
                String email = jwt.get().getClaimAsString("email");
                return Optional.ofNullable(email);
            }
        } catch (Exception e) {
            logger.debug("Error getting current user email", e);
        }
        return Optional.empty();
    }
    
    /**
     * Get current user roles from security context
     */
    public static Set<String> getCurrentUserRoles() {
        try {
            Optional<Authentication> auth = getCurrentAuthentication();
            if (auth.isPresent()) {
                return auth.get().getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .map(authority -> authority.startsWith("ROLE_") ? 
                         authority.substring(5) : authority)
                    .collect(Collectors.toSet());
            }
        } catch (Exception e) {
            logger.debug("Error getting current user roles", e);
        }
        return Collections.emptySet();
    }
    
    /**
     * Get current user authorities from security context
     */
    public static Set<String> getCurrentUserAuthorities() {
        try {
            Optional<Authentication> auth = getCurrentAuthentication();
            if (auth.isPresent()) {
                return auth.get().getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toSet());
            }
        } catch (Exception e) {
            logger.debug("Error getting current user authorities", e);
        }
        return Collections.emptySet();
    }
    
    /**
     * Check if current user has specific role
     */
    public static boolean hasRole(String role) {
        try {
            Set<String> roles = getCurrentUserRoles();
            return roles.contains(role.toUpperCase()) || 
                   roles.contains(role.toLowerCase()) ||
                   roles.contains(role);
        } catch (Exception e) {
            logger.debug("Error checking role: {}", role, e);
        }
        return false;
    }
    
    /**
     * Check if current user has any of the specified roles
     */
    public static boolean hasAnyRole(String... roles) {
        try {
            Set<String> userRoles = getCurrentUserRoles();
            for (String role : roles) {
                if (userRoles.contains(role.toUpperCase()) || 
                    userRoles.contains(role.toLowerCase()) ||
                    userRoles.contains(role)) {
                    return true;
                }
            }
        } catch (Exception e) {
            logger.debug("Error checking roles: {}", Arrays.toString(roles), e);
        }
        return false;
    }
    
    /**
     * Check if current user has all specified roles
     */
    public static boolean hasAllRoles(String... roles) {
        try {
            Set<String> userRoles = getCurrentUserRoles();
            for (String role : roles) {
                if (!userRoles.contains(role.toUpperCase()) && 
                    !userRoles.contains(role.toLowerCase()) &&
                    !userRoles.contains(role)) {
                    return false;
                }
            }
            return true;
        } catch (Exception e) {
            logger.debug("Error checking all roles: {}", Arrays.toString(roles), e);
        }
        return false;
    }
    
    /**
     * Check if current user is admin
     */
    public static boolean isAdmin() {
        return hasAnyRole("ADMIN", "ADMINISTRATOR");
    }
    
    /**
     * Check if current user is regular user
     */
    public static boolean isUser() {
        return hasRole("USER");
    }
    
    /**
     * Check if current user is authenticated
     */
    public static boolean isAuthenticated() {
        try {
            Optional<Authentication> auth = getCurrentAuthentication();
            return auth.isPresent() && auth.get().isAuthenticated() && 
                   !"anonymousUser".equals(auth.get().getName());
        } catch (Exception e) {
            logger.debug("Error checking authentication status", e);
        }
        return false;
    }
    
    /**
     * Check if current user is anonymous
     */
    public static boolean isAnonymous() {
        return !isAuthenticated();
    }
    
    /**
     * Get current user's full name from JWT
     */
    public static Optional<String> getCurrentUserFullName() {
        try {
            Optional<Jwt> jwt = getCurrentJwt();
            if (jwt.isPresent()) {
                Jwt token = jwt.get();
                
                // Try 'name' claim first
                String fullName = token.getClaimAsString("name");
                if (fullName != null && !fullName.trim().isEmpty()) {
                    return Optional.of(fullName);
                }
                
                // Build from first and last name
                String firstName = token.getClaimAsString("given_name");
                String lastName = token.getClaimAsString("family_name");
                
                if (firstName != null && lastName != null) {
                    return Optional.of(firstName + " " + lastName);
                } else if (firstName != null) {
                    return Optional.of(firstName);
                } else if (lastName != null) {
                    return Optional.of(lastName);
                }
                
                // Fallback to username
                return getCurrentUsername();
            }
        } catch (Exception e) {
            logger.debug("Error getting current user full name", e);
        }
        return Optional.empty();
    }
    
    /**
     * Get current user's first name from JWT
     */
    public static Optional<String> getCurrentUserFirstName() {
        try {
            Optional<Jwt> jwt = getCurrentJwt();
            if (jwt.isPresent()) {
                String firstName = jwt.get().getClaimAsString("given_name");
                return Optional.ofNullable(firstName);
            }
        } catch (Exception e) {
            logger.debug("Error getting current user first name", e);
        }
        return Optional.empty();
    }
    
    /**
     * Get current user's last name from JWT
     */
    public static Optional<String> getCurrentUserLastName() {
        try {
            Optional<Jwt> jwt = getCurrentJwt();
            if (jwt.isPresent()) {
                String lastName = jwt.get().getClaimAsString("family_name");
                return Optional.ofNullable(lastName);
            }
        } catch (Exception e) {
            logger.debug("Error getting current user last name", e);
        }
        return Optional.empty();
    }
    
    /**
     * Check if current user can access resource owned by specified user ID
     */
    public static boolean canAccessUserResource(String targetUserId) {
        try {
            // Admin can access any resource
            if (isAdmin()) {
                return true;
            }
            
            // User can access their own resources
            Optional<String> currentUserId = getCurrentUserId();
            return currentUserId.isPresent() && currentUserId.get().equals(targetUserId);
            
        } catch (Exception e) {
            logger.debug("Error checking resource access for user ID: {}", targetUserId, e);
        }
        return false;
    }
    
    /**
     * Check if current user can access resource owned by specified username
     */
    public static boolean canAccessUserResourceByUsername(String targetUsername) {
        try {
            // Admin can access any resource
            if (isAdmin()) {
                return true;
            }
            
            // User can access their own resources
            Optional<String> currentUsername = getCurrentUsername();
            return currentUsername.isPresent() && currentUsername.get().equals(targetUsername);
            
        } catch (Exception e) {
            logger.debug("Error checking resource access for username: {}", targetUsername, e);
        }
        return false;
    }
    
    /**
     * Get JWT token expiration time
     */
    public static Optional<Long> getTokenExpirationSeconds() {
        try {
            Optional<Jwt> jwt = getCurrentJwt();
            if (jwt.isPresent() && jwt.get().getExpiresAt() != null) {
                long expiresAt = jwt.get().getExpiresAt().getEpochSecond();
                long now = java.time.Instant.now().getEpochSecond();
                return Optional.of(Math.max(0, expiresAt - now));
            }
        } catch (Exception e) {
            logger.debug("Error getting token expiration", e);
        }
        return Optional.empty();
    }
    
    /**
     * Check if JWT token is about to expire (within 5 minutes)
     */
    public static boolean isTokenNearExpiration() {
        return isTokenNearExpiration(300); // 5 minutes
    }
    
    /**
     * Check if JWT token is about to expire within specified seconds
     */
    public static boolean isTokenNearExpiration(long warningSeconds) {
        try {
            Optional<Long> expirationSeconds = getTokenExpirationSeconds();
            return expirationSeconds.isPresent() && expirationSeconds.get() <= warningSeconds;
        } catch (Exception e) {
            logger.debug("Error checking token expiration warning", e);
        }
        return false;
    }
    
    /**
     * Get all JWT claims as a map
     */
    public static Map<String, Object> getCurrentJwtClaims() {
        try {
            Optional<Jwt> jwt = getCurrentJwt();
            if (jwt.isPresent()) {
                return new HashMap<>(jwt.get().getClaims());
            }
        } catch (Exception e) {
            logger.debug("Error getting JWT claims", e);
        }
        return Collections.emptyMap();
    }
    
    /**
     * Get specific claim from current JWT
     */
    public static Optional<Object> getCurrentJwtClaim(String claimName) {
        try {
            Optional<Jwt> jwt = getCurrentJwt();
            if (jwt.isPresent()) {
                Object claim = jwt.get().getClaim(claimName);
                return Optional.ofNullable(claim);
            }
        } catch (Exception e) {
            logger.debug("Error getting JWT claim: {}", claimName, e);
        }
        return Optional.empty();
    }
    
    /**
     * Get current user's session ID from JWT
     */
    public static Optional<String> getCurrentSessionId() {
        try {
            Optional<Jwt> jwt = getCurrentJwt();
            if (jwt.isPresent()) {
                String sessionId = jwt.get().getClaimAsString("session_state");
                return Optional.ofNullable(sessionId);
            }
        } catch (Exception e) {
            logger.debug("Error getting current session ID", e);
        }
        return Optional.empty();
    }
    
    /**
     * Log security context information for debugging
     */
    public static void logSecurityContext() {
        try {
            Optional<Authentication> auth = getCurrentAuthentication();
            if (auth.isPresent()) {
                logger.info("Security Context - Username: {}, Roles: {}, Authenticated: {}", 
                           getCurrentUsername().orElse("N/A"),
                           getCurrentUserRoles(),
                           auth.get().isAuthenticated());
            } else {
                logger.info("Security Context - No authentication found");
            }
        } catch (Exception e) {
            logger.warn("Error logging security context", e);
        }
    }
    
    /**
     * Clear security context (for logout)
     */
    public static void clearSecurityContext() {
        try {
            SecurityContextHolder.clearContext();
            logger.debug("Security context cleared");
        } catch (Exception e) {
            logger.warn("Error clearing security context", e);
        }
    }
    
    /**
     * Create authentication summary for logging/debugging
     */
    public static String getAuthenticationSummary() {
        try {
            if (!isAuthenticated()) {
                return "Anonymous user";
            }
            
            return String.format("User: %s, Roles: %s, Session: %s",
                getCurrentUsername().orElse("Unknown"),
                getCurrentUserRoles(),
                getCurrentSessionId().orElse("N/A"));
                
        } catch (Exception e) {
            logger.debug("Error creating authentication summary", e);
            return "Authentication summary unavailable";
        }
    }
    
    /**
     * Validate if current user context is properly set up
     */
    public static boolean isSecurityContextValid() {
        try {
            Optional<Authentication> auth = getCurrentAuthentication();
            if (auth.isEmpty()) {
                return false;
            }
            
            Authentication authentication = auth.get();
            
            // Check if authenticated
            if (!authentication.isAuthenticated()) {
                return false;
            }
            
            // Check if has valid name
            String name = authentication.getName();
            if (name == null || name.trim().isEmpty() || "anonymousUser".equals(name)) {
                return false;
            }
            
            // Check if has authorities
            if (authentication.getAuthorities() == null || authentication.getAuthorities().isEmpty()) {
                return false;
            }
            
            return true;
            
        } catch (Exception e) {
            logger.debug("Error validating security context", e);
            return false;
        }
    }
}