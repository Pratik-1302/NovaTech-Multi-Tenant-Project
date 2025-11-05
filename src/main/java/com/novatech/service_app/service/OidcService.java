package com.novatech.service_app.service;

import com.novatech.service_app.entity.SsoConfiguration;
import com.novatech.service_app.repository.SsoConfigurationRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Base64;
import java.util.Map;
import java.util.Optional;

/**
 * OIDC Service - Handles OpenID Connect token exchange and user info retrieval
 */
@Service
public class OidcService {

    private static final Logger logger = LoggerFactory.getLogger(OidcService.class);

    @Autowired
    private SsoConfigurationRepository ssoConfigRepository;

    /**
     * ✅ Exchange authorization code for access token
     * This is the core of OIDC Authorization Code Flow
     */
    public Map<String, Object> exchangeCodeForToken(String authorizationCode) throws Exception {
        logger.info("=== EXCHANGING OIDC CODE FOR TOKEN ===");

        // Get OIDC config from database
        Optional<SsoConfiguration> configOpt = ssoConfigRepository.findBySsoType("OIDC");

        if (configOpt.isEmpty()) {
            throw new IllegalStateException("OIDC configuration not found in database");
        }

        SsoConfiguration config = configOpt.get();

        // Validate required fields
        if (config.getTokenEndpoint() == null || config.getTokenEndpoint().isBlank()) {
            throw new IllegalStateException("OIDC token endpoint not configured");
        }

        // Prepare token request
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        // Basic Auth: Base64(client_id:client_secret)
        String auth = config.getClientId() + ":" + config.getClientSecret();
        String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes());
        headers.set("Authorization", "Basic " + encodedAuth);

        // Request body
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "authorization_code");
        body.add("code", authorizationCode);
        body.add("redirect_uri", config.getRedirectUri());
        body.add("client_id", config.getClientId());

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        logger.info("📤 Sending token request to: {}", config.getTokenEndpoint());

        try {
            // Make token exchange request
            ResponseEntity<Map> response = restTemplate.exchange(
                    config.getTokenEndpoint(),
                    HttpMethod.POST,
                    request,
                    Map.class
            );

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                logger.info("✅ Token exchange successful");
                return response.getBody();
            } else {
                throw new RuntimeException("Token exchange failed with status: " + response.getStatusCode());
            }

        } catch (Exception e) {
            logger.error("❌ Token exchange failed: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to exchange authorization code: " + e.getMessage(), e);
        }
    }

    /**
     * ✅ Get user info from OIDC provider
     */
    public Map<String, Object> getUserInfo(String accessToken) throws Exception {
        logger.info("=== FETCHING OIDC USER INFO ===");

        // Get OIDC config from database
        Optional<SsoConfiguration> configOpt = ssoConfigRepository.findBySsoType("OIDC");

        if (configOpt.isEmpty()) {
            throw new IllegalStateException("OIDC configuration not found in database");
        }

        SsoConfiguration config = configOpt.get();

        // Check if userinfo endpoint is configured
        if (config.getUserinfoEndpoint() == null || config.getUserinfoEndpoint().isBlank()) {
            logger.warn("⚠️ UserInfo endpoint not configured, skipping user info fetch");
            return Map.of();
        }

        // Prepare userinfo request
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);

        HttpEntity<String> request = new HttpEntity<>(headers);

        logger.info("📤 Sending userinfo request to: {}", config.getUserinfoEndpoint());

        try {
            ResponseEntity<Map> response = restTemplate.exchange(
                    config.getUserinfoEndpoint(),
                    HttpMethod.GET,
                    request,
                    Map.class
            );

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                logger.info("✅ UserInfo retrieved successfully");
                return response.getBody();
            } else {
                throw new RuntimeException("UserInfo request failed with status: " + response.getStatusCode());
            }

        } catch (Exception e) {
            logger.error("❌ UserInfo fetch failed: {}", e.getMessage(), e);
            // Don't throw - userinfo is optional
            return Map.of();
        }
    }

    /**
     * ✅ Parse ID token (JWT) from token response
     */
    public Map<String, Object> parseIdToken(String idToken) {
        try {
            // Split JWT into parts
            String[] parts = idToken.split("\\.");
            if (parts.length != 3) {
                throw new IllegalArgumentException("Invalid JWT format");
            }

            // Decode payload (Base64URL)
            String payload = new String(Base64.getUrlDecoder().decode(parts[1]));

            // Parse JSON (simple approach - for production use a JSON library)
            logger.info("✅ ID Token payload: {}", payload);

            // For now, return empty map - will parse properly later
            return Map.of("raw_payload", payload);

        } catch (Exception e) {
            logger.error("❌ Error parsing ID token: {}", e.getMessage());
            return Map.of();
        }
    }
}
//working-version