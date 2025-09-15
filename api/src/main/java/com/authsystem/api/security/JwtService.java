package com.authsystem.api.security;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Service;

import com.authsystem.api.dto.auth.UserInfo;
import com.authsystem.api.exception.AuthenticationException;

@Service
public class JwtService {
    
    private static final Logger logger = LoggerFactory.getLogger(JwtService.class);
    
    private final JwtDecoder jwtDecoder;
    
    @Value("${keycloak.resource:}")
    private String clientId;
    
    @Value("${keycloak.realm:}")
    private String expectedRealm;
    
    @Value("${app.security.jwt.leeway:60}")
    private long clockSkewLeewaySeconds;
    
    @Autowired
    public JwtService(JwtDecoder jwtDecoder) {
        this.jwtDecoder = jwtDecoder;
    }
    
    /**
     * Decode and validate JWT token
     */
    public Jwt decodeToken(String token) {
        try {
            if (token == null || token.trim().isEmpty()) {
                throw AuthenticationException.tokenMissing();
            }
            
            // Remove Bearer prefix if present
            if (token.startsWith("Bearer ")) {
                token = token.substring(7);
            }
            
            return jwtDecoder.decode(token);
            
        } catch (JwtException e) {
            logger.warn("JWT decoding failed: {}", e.getMessage());
            throw AuthenticationException.tokenInvalid();
        } catch (Exception e) {
            logger.error("Unexpected error decoding JWT", e);
            throw AuthenticationException.tokenInvalid();
        }
    }
    
    /**
     * Validate JWT token without throwing exceptions
     */
    public boolean isTokenValid(String token) {
        try {
            decodeToken(token);
            return true;
        } catch (Exception e) {
            logger.debug("Token validation failed: {}", e.getMessage());
            return false;
        }
    }
    
    /**
     * Extract username from JWT token
     */
    public String extractUsername(Jwt jwt) {
        try {
            // Try preferred_username first (Keycloak standard)
            String username = jwt.getClaimAsString("preferred_username");
            if (username != null && !username.trim().isEmpty()) {
                return username;
            }
            
            // Fallback to subject
            username = jwt.getSubject();
            if (username != null && !username.trim().isEmpty()) {
                return username;
            }
            
            // Last fallback to email
            username = jwt.getClaimAsString("email");
            if (username != null && !username.trim().isEmpty()) {
                return username;
            }
            
            throw new IllegalStateException("No valid username found in JWT");
            
        } catch (Exception e) {
            logger.warn("Error extracting username from JWT", e);
            throw AuthenticationException.tokenInvalid();
        }
    }
    
    /**
     * Extract username from token string
     */
    public String extractUsername(String token) {
        Jwt jwt = decodeToken(token);
        return extractUsername(jwt);
    }
    
    /**
     * Extract email from JWT token
     */
    public String extractEmail(Jwt jwt) {
        try {
            return jwt.getClaimAsString("email");
        } catch (Exception e) {
            logger.debug("Error extracting email from JWT", e);
            return null;
        }
    }
    
    /**
     * Extract user ID (subject) from JWT token
     */
    public String extractUserId(Jwt jwt) {
        try {
            return jwt.getSubject();
        } catch (Exception e) {
            logger.debug("Error extracting user ID from JWT", e);
            return null;
        }
    }
    
    /**
     * Extract first name from JWT token
     */
    public String extractFirstName(Jwt jwt) {
        try {
            return jwt.getClaimAsString("given_name");
        } catch (Exception e) {
            logger.debug("Error extracting first name from JWT", e);
            return null;
        }
    }
    
    /**
     * Extract last name from JWT token
     */
    public String extractLastName(Jwt jwt) {
        try {
            return jwt.getClaimAsString("family_name");
        } catch (Exception e) {
            logger.debug("Error extracting last name from JWT", e);
            return null;
        }
    }
    
    /**
     * Extract full name from JWT token
     */
    public String extractFullName(Jwt jwt) {
        try {
            // Try 'name' claim first
            String fullName = jwt.getClaimAsString("name");
            if (fullName != null && !fullName.trim().isEmpty()) {
                return fullName;
            }
            
            // Build from first and last name
            String firstName = extractFirstName(jwt);
            String lastName = extractLastName(jwt);
            
            if (firstName != null && lastName != null) {
                return firstName + " " + lastName;
            } else if (firstName != null) {
                return firstName;
            } else if (lastName != null) {
                return lastName;
            }
            
            // Fallback to username
            return extractUsername(jwt);
            
        } catch (Exception e) {
            logger.debug("Error extracting full name from JWT", e);
            return extractUsername(jwt);
        }
    }
    
    /**
     * Extract all roles from JWT token (realm + client roles)
     */
    public List<String> extractRoles(Jwt jwt) {
        Set<String> allRoles = new HashSet<>();
        
        try {
            // Extract realm roles
            Map<String, Object> realmAccess = jwt.getClaimAsMap("realm_access");
            if (realmAccess != null && realmAccess.containsKey("roles")) {
                @SuppressWarnings("unchecked")
                List<String> realmRoles = (List<String>) realmAccess.get("roles");
                if (realmRoles != null) {
                    allRoles.addAll(realmRoles);
                }
            }
            
            // Extract client roles
            if (clientId != null && !clientId.isEmpty()) {
                Map<String, Object> resourceAccess = jwt.getClaimAsMap("resource_access");
                if (resourceAccess != null && resourceAccess.containsKey(clientId)) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> clientAccess = (Map<String, Object>) resourceAccess.get(clientId);
                    if (clientAccess != null && clientAccess.containsKey("roles")) {
                        @SuppressWarnings("unchecked")
                        List<String> clientRoles = (List<String>) clientAccess.get("roles");
                        if (clientRoles != null) {
                            allRoles.addAll(clientRoles);
                        }
                    }
                }
            }
            
            // Add default USER role if no roles found
            if (allRoles.isEmpty()) {
                allRoles.add("USER");
            }
            
        } catch (Exception e) {
            logger.warn("Error extracting roles from JWT, using default USER role", e);
            allRoles.add("USER");
        }
        
        return new ArrayList<>(allRoles);
    }
    
    /**
     * Check if JWT token has specific role
     */
    public boolean hasRole(Jwt jwt, String role) {
        List<String> roles = extractRoles(jwt);
        return roles.stream().anyMatch(r -> 
            r.equalsIgnoreCase(role) || 
            r.equalsIgnoreCase("ROLE_" + role) ||
            r.equalsIgnoreCase(role.replace("ROLE_", ""))
        );
    }
    
    /**
     * Check if JWT token has admin role
     */
    public boolean hasAdminRole(Jwt jwt) {
        return hasRole(jwt, "ADMIN") || hasRole(jwt, "ADMINISTRATOR");
    }
    
    /**
     * Get token expiration time
     */
    public Instant getTokenExpiration(Jwt jwt) {
        return jwt.getExpiresAt();
    }
    
    /**
     * Get token expiration as LocalDateTime
     */
    public LocalDateTime getTokenExpirationAsLocalDateTime(Jwt jwt) {
        Instant expiration = getTokenExpiration(jwt);
        return expiration != null ? 
            LocalDateTime.ofInstant(expiration, ZoneId.systemDefault()) : 
            null;
    }
    
    /**
     * Get remaining token lifetime in seconds
     */
    public long getTokenRemainingSeconds(Jwt jwt) {
        try {
            Instant expiration = getTokenExpiration(jwt);
            if (expiration != null) {
                long remaining = expiration.getEpochSecond() - Instant.now().getEpochSecond();
                return Math.max(0, remaining);
            }
        } catch (Exception e) {
            logger.debug("Error calculating remaining token time", e);
        }
        return 0;
    }
    
    /**
     * Check if token is expired
     */
    public boolean isTokenExpired(Jwt jwt) {
        try {
            Instant expiration = getTokenExpiration(jwt);
            return expiration != null && expiration.isBefore(Instant.now());
        } catch (Exception e) {
            logger.debug("Error checking token expiration", e);
            return true; // Assume expired if can't check
        }
    }
    
    /**
     * Check if token is about to expire (within warning threshold)
     */
    public boolean isTokenNearExpiration(Jwt jwt, Duration warningThreshold) {
        try {
            Instant expiration = getTokenExpiration(jwt);
            if (expiration != null) {
                Instant warningTime = Instant.now().plus(warningThreshold);
                return expiration.isBefore(warningTime);
            }
        } catch (Exception e) {
            logger.debug("Error checking token expiration warning", e);
        }
        return false;
    }
    
    /**
     * Check if token is near expiration (default 5 minutes)
     */
    public boolean isTokenNearExpiration(Jwt jwt) {
        return isTokenNearExpiration(jwt, Duration.ofMinutes(5));
    }
    
    /**
     * Get token issued time
     */
    public Instant getTokenIssuedAt(Jwt jwt) {
        return jwt.getIssuedAt();
    }
    
    /**
     * Get token issuer
     */
    public String getTokenIssuer(Jwt jwt) {
        return jwt.getIssuer() != null ? jwt.getIssuer().toString() : null;
    }
    
    /**
     * Get all token audiences
     */
    public List<String> getTokenAudiences(Jwt jwt) {
        return jwt.getClaimAsStringList("aud");
    }
    
    /**
     * Get session ID from token
     */
    public String getSessionId(Jwt jwt) {
        try {
            return jwt.getClaimAsString("session_state");
        } catch (Exception e) {
            logger.debug("Error extracting session ID from JWT", e);
            return null;
        }
    }
    
    /**
     * Get authorized party (client ID that requested the token)
     */
    public String getAuthorizedParty(Jwt jwt) {
        try {
            return jwt.getClaimAsString("azp");
        } catch (Exception e) {
            logger.debug("Error extracting authorized party from JWT", e);
            return null;
        }
    }
    
    /**
     * Get all JWT claims as a map
     */
    public Map<String, Object> getAllClaims(Jwt jwt) {
        try {
            return new HashMap<>(jwt.getClaims());
        } catch (Exception e) {
            logger.debug("Error extracting all claims from JWT", e);
            return Collections.emptyMap();
        }
    }
    
    /**
     * Get specific claim from JWT
     */
    public Object getClaim(Jwt jwt, String claimName) {
        try {
            return jwt.getClaim(claimName);
        } catch (Exception e) {
            logger.debug("Error extracting claim '{}' from JWT", claimName, e);
            return null;
        }
    }
    
    /**
     * Convert JWT to UserInfo DTO
     */
    public UserInfo convertToUserInfo(Jwt jwt) {
        try {
            UserInfo userInfo = new UserInfo();
            userInfo.setId(null); // We don't have UUID in JWT, will be set by service layer
            userInfo.setUsername(extractUsername(jwt));
            userInfo.setEmail(extractEmail(jwt));
            userInfo.setEnabled(true); // Assume enabled if token is valid
            userInfo.setRoles(extractRoles(jwt));
            userInfo.setCreatedAt(null); // Not available in JWT
            userInfo.setLastLogin(null); // Not available in JWT
            
            return userInfo;
            
        } catch (Exception e) {
            logger.error("Error converting JWT to UserInfo", e);
            throw AuthenticationException.tokenInvalid();
        }
    }
    
    /**
     * Create token summary for logging
     */
    public String getTokenSummary(Jwt jwt) {
        try {
            return String.format(
                "JWT{username=%s, roles=%s, expires=%s, session=%s}",
                extractUsername(jwt),
                extractRoles(jwt),
                getTokenExpirationAsLocalDateTime(jwt),
                getSessionId(jwt)
            );
        } catch (Exception e) {
            return "JWT{invalid}";
        }
    }
    
    /**
     * Validate token format without full decoding
     */
    public boolean isTokenFormatValid(String token) {
        try {
            if (token == null || token.trim().isEmpty()) {
                return false;
            }
            
            // Remove Bearer prefix if present
            if (token.startsWith("Bearer ")) {
                token = token.substring(7);
            }
            
            // Check JWT format (header.payload.signature)
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                return false;
            }
            
            // Basic validation of parts
            for (String part : parts) {
                if (part.isEmpty()) {
                    return false;
                }
            }
            
            return true;
            
        } catch (Exception e) {
            logger.debug("Error validating token format", e);
            return false;
        }
    }
}