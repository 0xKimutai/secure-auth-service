package com.authsystem.api.security;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

@Component
public class JwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {
    
    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationConverter.class);
    
    @Value("${app.security.jwt.authorities-claim-name:realm_access}")
    private String authoritiesClaimName;
    
    @Value("${app.security.jwt.authority-prefix:ROLE_}")
    private String authorityPrefix;
    
    @Value("${app.security.jwt.principal-claim-name:preferred_username}")
    private String principalClaimName;
    
    @Value("${keycloak.resource:}")
    private String clientId;
    
    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        logger.debug("Converting JWT to Authentication token");
        
        try {
            // Extract authorities (roles) from JWT
            Collection<GrantedAuthority> authorities = extractAuthorities(jwt);
            
            // Extract principal name (usually username)
            String principalName = extractPrincipalName(jwt);
            
            logger.debug("JWT converted successfully for user: {} with authorities: {}", 
                        principalName, authorities);
            
            return new JwtAuthenticationToken(jwt, authorities, principalName);
            
        } catch (Exception e) {
            logger.error("Error converting JWT to Authentication token", e);
            // Return token with no authorities if conversion fails
            return new JwtAuthenticationToken(jwt, Collections.emptyList());
        }
    }
    
    /**
     * Extract authorities (roles) from JWT token
     */
    private Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
        Set<GrantedAuthority> authorities = new HashSet<>();
        
        try {
            // Extract realm roles
            Collection<String> realmRoles = extractRealmRoles(jwt);
            if (realmRoles != null && !realmRoles.isEmpty()) {
                authorities.addAll(realmRoles.stream()
                    .map(role -> new SimpleGrantedAuthority(authorityPrefix + role.toUpperCase()))
                    .collect(Collectors.toSet()));
            }
            
            // Extract client roles
            Collection<String> clientRoles = extractClientRoles(jwt);
            if (clientRoles != null && !clientRoles.isEmpty()) {
                authorities.addAll(clientRoles.stream()
                    .map(role -> new SimpleGrantedAuthority(authorityPrefix + role.toUpperCase()))
                    .collect(Collectors.toSet()));
            }
            
            // Add default USER role if no roles found
            if (authorities.isEmpty()) {
                logger.debug("No roles found in JWT, adding default USER role");
                authorities.add(new SimpleGrantedAuthority(authorityPrefix + "USER"));
            }
            
        } catch (Exception e) {
            logger.warn("Error extracting authorities from JWT, using default USER role", e);
            authorities.add(new SimpleGrantedAuthority(authorityPrefix + "USER"));
        }
        
        return authorities;
    }
    
    /**
     * Extract realm roles from JWT
     */
    private Collection<String> extractRealmRoles(Jwt jwt) {
        try {
            Map<String, Object> realmAccess = jwt.getClaimAsMap("realm_access");
            if (realmAccess != null && realmAccess.containsKey("roles")) {
                @SuppressWarnings("unchecked")
                List<String> roles = (List<String>) realmAccess.get("roles");
                return roles != null ? roles : Collections.emptyList();
            }
        } catch (Exception e) {
            logger.debug("Error extracting realm roles", e);
        }
        return Collections.emptyList();
    }
    
    /**
     * Extract client-specific roles from JWT
     */
    private Collection<String> extractClientRoles(Jwt jwt) {
        try {
            if (clientId != null && !clientId.isEmpty()) {
                Map<String, Object> resourceAccess = jwt.getClaimAsMap("resource_access");
                if (resourceAccess != null && resourceAccess.containsKey(clientId)) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> clientAccess = (Map<String, Object>) resourceAccess.get(clientId);
                    if (clientAccess != null && clientAccess.containsKey("roles")) {
                        @SuppressWarnings("unchecked")
                        List<String> roles = (List<String>) clientAccess.get("roles");
                        return roles != null ? roles : Collections.emptyList();
                    }
                }
            }
        } catch (Exception e) {
            logger.debug("Error extracting client roles", e);
        }
        return Collections.emptyList();
    }
    
    /**
     * Extract principal name from JWT
     */
    private String extractPrincipalName(Jwt jwt) {
        try {
            String principalName = jwt.getClaimAsString(principalClaimName);
            if (principalName != null && !principalName.isEmpty()) {
                return principalName;
            }
            
            // Fallback to 'sub' claim if preferred_username is not available
            principalName = jwt.getClaimAsString("sub");
            if (principalName != null && !principalName.isEmpty()) {
                return principalName;
            }
            
            // Last fallback to 'email' claim
            principalName = jwt.getClaimAsString("email");
            if (principalName != null && !principalName.isEmpty()) {
                return principalName;
            }
            
        } catch (Exception e) {
            logger.warn("Error extracting principal name from JWT", e);
        }
        
        // Ultimate fallback
        return "unknown_user";
    }
    
    /**
     * Get all roles from JWT (realm + client roles combined)
     */
    public Collection<String> getAllRoles(Jwt jwt) {
        Set<String> allRoles = new HashSet<>();
        
        // Add realm roles
        allRoles.addAll(extractRealmRoles(jwt));
        
        // Add client roles
        allRoles.addAll(extractClientRoles(jwt));
        
        return allRoles;
    }
    
    /**
     * Check if JWT contains specific role
     */
    public boolean hasRole(Jwt jwt, String role) {
        Collection<String> roles = getAllRoles(jwt);
        return roles.contains(role) || roles.contains(role.toUpperCase()) || roles.contains(role.toLowerCase());
    }
    
    /**
     * Check if JWT contains admin role
     */
    public boolean hasAdminRole(Jwt jwt) {
        return hasRole(jwt, "ADMIN") || hasRole(jwt, "admin") || 
               hasRole(jwt, "ADMINISTRATOR") || hasRole(jwt, "administrator");
    }
    
    /**
     * Check if JWT contains user role
     */
    public boolean hasUserRole(Jwt jwt) {
        return hasRole(jwt, "USER") || hasRole(jwt, "user");
    }
    
    /**
     * Get user email from JWT
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
     * Get user's first name from JWT
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
     * Get user's last name from JWT
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
     * Get user's full name from JWT
     */
    public String extractFullName(Jwt jwt) {
        try {
            String fullName = jwt.getClaimAsString("name");
            if (fullName != null && !fullName.isEmpty()) {
                return fullName;
            }
            
            // Construct from first and last name
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
            return extractPrincipalName(jwt);
            
        } catch (Exception e) {
            logger.debug("Error extracting full name from JWT", e);
            return extractPrincipalName(jwt);
        }
    }
    
    /**
     * Check if JWT token is expired
     */
    public boolean isTokenExpired(Jwt jwt) {
        try {
            if (jwt.getExpiresAt() != null) {
                return jwt.getExpiresAt().isBefore(java.time.Instant.now());
            }
            return false;
        } catch (Exception e) {
            logger.warn("Error checking token expiration", e);
            return true; // Assume expired if we can't check
        }
    }
    
    /**
     * Get token expiration time in seconds from now
     */
    public long getTokenExpirationSeconds(Jwt jwt) {
        try {
            if (jwt.getExpiresAt() != null) {
                long expiresAt = jwt.getExpiresAt().getEpochSecond();
                long now = java.time.Instant.now().getEpochSecond();
                return Math.max(0, expiresAt - now);
            }
        } catch (Exception e) {
            logger.debug("Error calculating token expiration", e);
        }
        return 0;
    }
}