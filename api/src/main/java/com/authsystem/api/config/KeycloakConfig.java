package com.authsystem.api.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
public class KeycloakConfig {
    
    @Value("${keycloak.auth-server-url}")
    private String authServerUrl;
    
    @Value("${keycloak.realm}")
    private String realm;
    
    @Value("${keycloak.resource}")
    private String clientId;
    
    @Value("${keycloak.credentials.secret:}")
    private String clientSecret;
    
    @Value("${keycloak.public-client:true}")
    private boolean publicClient;
    
    @Value("${keycloak.bearer-only:true}")
    private boolean bearerOnly;
    
    @Value("${keycloak.ssl-required:external}")
    private String sslRequired;
    
    @Value("${keycloak.use-resource-role-mappings:false}")
    private boolean useResourceRoleMappings;
    
    @Value("${keycloak.cors:true}")
    private boolean corsEnabled;
    
    @Value("${keycloak.cors-max-age:1000}")
    private int corsMaxAge;
    
    @Value("${keycloak.cors-allowed-methods:POST,PUT,DELETE,GET}")
    private String corsAllowedMethods;
    
    @Value("${keycloak.cors-allowed-headers:X-Requested-With,Content-Type,Authorization}")
    private String corsAllowedHeaders;
    
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
    
    /**
     * Get Keycloak server URL
     */
    public String getAuthServerUrl() {
        return authServerUrl;
    }
    
    /**
     * Get Keycloak realm name
     */
    public String getRealm() {
        return realm;
    }
    
    /**
     * Get Keycloak client ID
     */
    public String getClientId() {
        return clientId;
    }
    
    /**
     * Get Keycloak client secret
     */
    public String getClientSecret() {
        return clientSecret;
    }
    
    /**
     * Check if client is public
     */
    public boolean isPublicClient() {
        return publicClient;
    }
    
    /**
     * Check if bearer-only mode is enabled
     */
    public boolean isBearerOnly() {
        return bearerOnly;
    }
    
    /**
     * Get SSL requirement setting
     */
    public String getSslRequired() {
        return sslRequired;
    }
    
    /**
     * Check if using resource role mappings
     */
    public boolean isUseResourceRoleMappings() {
        return useResourceRoleMappings;
    }
    
    /**
     * Check if CORS is enabled
     */
    public boolean isCorsEnabled() {
        return corsEnabled;
    }
    
    /**
     * Get CORS max age
     */
    public int getCorsMaxAge() {
        return corsMaxAge;
    }
    
    /**
     * Get CORS allowed methods
     */
    public String getCorsAllowedMethods() {
        return corsAllowedMethods;
    }
    
    /**
     * Get CORS allowed headers
     */
    public String getCorsAllowedHeaders() {
        return corsAllowedHeaders;
    }
    
    /**
     * Build Keycloak realm URL
     */
    public String getRealmUrl() {
        return String.format("%s/realms/%s", authServerUrl, realm);
    }
    
    /**
     * Build Keycloak token endpoint URL
     */
    public String getTokenUrl() {
        return String.format("%s/realms/%s/protocol/openid-connect/token", authServerUrl, realm);
    }
    
    /**
     * Build Keycloak user info endpoint URL
     */
    public String getUserInfoUrl() {
        return String.format("%s/realms/%s/protocol/openid-connect/userinfo", authServerUrl, realm);
    }
    
    /**
     * Build Keycloak logout endpoint URL
     */
    public String getLogoutUrl() {
        return String.format("%s/realms/%s/protocol/openid-connect/logout", authServerUrl, realm);
    }
    
    /**
     * Build Keycloak JWK Set URI
     */
    public String getJwkSetUri() {
        return String.format("%s/realms/%s/protocol/openid-connect/certs", authServerUrl, realm);
    }
    
    /**
     * Build Keycloak admin users endpoint URL
     */
    public String getAdminUsersUrl() {
        return String.format("%s/admin/realms/%s/users", authServerUrl, realm);
    }
    
    /**
     * Build Keycloak issuer URI
     */
    public String getIssuerUri() {
        return getRealmUrl();
    }
    
    /**
     * Get configuration summary for logging
     */
    public String getConfigSummary() {
        return String.format(
            "Keycloak Config: realm=%s, clientId=%s, authServerUrl=%s, publicClient=%s, bearerOnly=%s",
            realm, clientId, authServerUrl, publicClient, bearerOnly
        );
    }
    
    /**
     * Validate configuration
     */
    public boolean isConfigurationValid() {
        return authServerUrl != null && !authServerUrl.trim().isEmpty() &&
               realm != null && !realm.trim().isEmpty() &&
               clientId != null && !clientId.trim().isEmpty();
    }
    
    /**
     * Get client authentication method
     */
    public String getClientAuthenticationMethod() {
        return publicClient ? "none" : "client_secret_basic";
    }
    
    /**
     * Get authorization grant type
     */
    public String getAuthorizationGrantType() {
        return "authorization_code";
    }
    
    /**
     * Get redirect URI pattern (for frontend integration)
     */
    public String getRedirectUriPattern() {
        return "{baseUrl}/login/oauth2/code/{registrationId}";
    }
}