package de.coldtea.verborum.msuser.user.service.impl;

import de.coldtea.verborum.msuser.user.dto.UserRequestDTO;
import de.coldtea.verborum.msuser.user.dto.UserResponseDTO;
import de.coldtea.verborum.msuser.user.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@Service
@Slf4j
public class UserServiceImpl implements UserService {
    private final WebClient webClient;
    private final String keycloakUrl;
    private final String realm;
    private final String clientId;
    private final String clientSecret;

    public UserServiceImpl(
            @Value("${keycloak.auth-server-url}") String keycloakUrl,
            @Value("${keycloak.realm}") String realm,
            @Value("${keycloak.resource}") String clientId,
            @Value("${keycloak.credentials.secret}") String clientSecret) {
        this.keycloakUrl = keycloakUrl;        // http://localhost:8081
        this.realm = realm;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.webClient = WebClient.builder()
                .baseUrl(keycloakUrl)
                .build();
    }

    @Override
    public String createUser(UserRequestDTO userRequestDTO) {
        try {
            // Create user request body
            Map<String, Object> user = new HashMap<>();
            user.put("username", userRequestDTO.getEmail());
            user.put("email", userRequestDTO.getEmail());
            user.put("enabled", true);

            // Add credentials
            Map<String, Object> credential = new HashMap<>();
            credential.put("type", "password");
            credential.put("value", userRequestDTO.getPassword());
            credential.put("temporary", false);
            user.put("credentials", Collections.singletonList(credential));

            // Get admin token first
            String adminToken = getAdminToken();

            // Create user in Keycloak
            ResponseEntity<Void> response = webClient.post()
                    .uri("/admin/realms/{realm}/users", realm)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(user)
                    .retrieve()
                    .toBodilessEntity()
                    .block();

            // Get user ID from Location header
            String location = response.getHeaders().getFirst(HttpHeaders.LOCATION);
            return location.substring(location.lastIndexOf("/") + 1);

        } catch (Exception e) {
            log.error("Error creating user in Keycloak", e);
            throw new RuntimeException("Failed to create user in Keycloak", e);
        }
    }

    @Override
    public UserResponseDTO getUser(String userId) {
        try {
            String adminToken = getAdminToken();

            return webClient.get()
                    .uri("/admin/realms/{realm}/users/{userId}", realm, userId)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                    .retrieve()
                    .bodyToMono(UserResponseDTO.class)
                    .block();
        } catch (Exception e) {
            log.error("Error fetching user from Keycloak", e);
            throw new RuntimeException("Failed to fetch user from Keycloak", e);
        }
    }

    @Override
    public String getAccessToken(String username, String password) {
        try {
            MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
            formData.add("grant_type", "password");
            formData.add("client_id", clientId);
            formData.add("client_secret", clientSecret);
            formData.add("username", username);
            formData.add("password", password);

            log.debug("Token request details:");
            log.debug("URL: {}/realms/{}/protocol/openid-connect/token", keycloakUrl, realm);
            log.debug("Client ID: {}", clientId);
            log.debug("Grant Type: password");
            // Don't log secrets or passwords

            return webClient.post()
                    .uri("/realms/{realm}/protocol/openid-connect/token", realm)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(BodyInserters.fromFormData(formData))
                    .retrieve()
                    .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                    .block()
                    .get("access_token")
                    .toString();

        } catch (WebClientResponseException e) {
            log.error("Token request failed. Status: {}, Body: {}",
                    e.getStatusCode(), e.getResponseBodyAsString());
            throw new RuntimeException("Failed to get access token: " + e.getMessage(), e);
        }
    }

    private String getAdminToken() {
        try {
            MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
            formData.add("grant_type", "password");
            formData.add("client_id", "admin-cli");  // Use admin-cli client
            formData.add("username", "admin");       // Your Keycloak admin username
            formData.add("password", "admin");       // Your Keycloak admin password

            log.info("Attempting to get admin token from: {}/realms/master/protocol/openid-connect/token", keycloakUrl);

            Map<String, String> tokenResponse = webClient.post()
                    .uri("/realms/master/protocol/openid-connect/token")  // Use master realm
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(BodyInserters.fromFormData(formData))
                    .retrieve()
                    .bodyToMono(new ParameterizedTypeReference<Map<String, String>>() {})
                    .block();

            return tokenResponse.get("access_token");
        } catch (WebClientResponseException e) {
            log.error("Admin token request failed. Status: {}, Body: {}",
                    e.getStatusCode(), e.getResponseBodyAsString());
            throw new RuntimeException("Failed to get admin token: " + e.getMessage(), e);
        }
    }
}

