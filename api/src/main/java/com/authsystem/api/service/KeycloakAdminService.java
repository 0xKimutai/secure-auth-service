package com.authsystem.api.service;

import com.authsystem.api.config.KeycloakConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

@Service
public class KeycloakAdminService {

    private final KeycloakConfig keycloakConfig;
    private final RestTemplate restTemplate;

    @Autowired
    public KeycloakAdminService(KeycloakConfig keycloakConfig, RestTemplate restTemplate) {
        this.keycloakConfig = keycloakConfig;
        this.restTemplate = restTemplate;
    }

    /**
     * Get access token for Keycloak Admin API using client credentials
     */
    public String getAdminAccessToken() {
        String url = keycloakConfig.getTokenUrl();

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        String body = "grant_type=client_credentials" +
                      "&client_id=" + keycloakConfig.getClientId() +
                      "&client_secret=" + keycloakConfig.getClientSecret();

        HttpEntity<String> request = new HttpEntity<>(body, headers);

        ResponseEntity<Map> response = restTemplate.postForEntity(url, request, Map.class);
        if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
            return response.getBody().get("access_token").toString();
        }
        throw new RuntimeException("Failed to get Keycloak admin token");
    }

    /**
     * Create a new user in Keycloak
     */
    public void createUser(String username, String email, String password, String mobile) {
        String token = getAdminAccessToken();
        String url = keycloakConfig.getAdminUsersUrl();

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(token);

        Map<String, Object> user = new HashMap<>();
        user.put("username", username);
        user.put("email", email);
        user.put("enabled", true);
        user.put("emailVerified", true);

        Map<String, String> credentials = new HashMap<>();
        credentials.put("type", "password");
        credentials.put("value", password);
        credentials.put("temporary", "false");

        user.put("credentials", new Map[]{credentials});
        if (mobile != null && !mobile.isEmpty()) {
            user.put("attributes", Map.of("mobileNumber", mobile));
        }

        HttpEntity<Map<String, Object>> request = new HttpEntity<>(user, headers);
        restTemplate.postForEntity(url, request, String.class);
    }
}
