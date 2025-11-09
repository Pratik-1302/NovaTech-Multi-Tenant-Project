package com.novatech.service_app.service;

import com.fasterxml.jackson.core.type.TypeReference; // ✅ IMPORT
import com.fasterxml.jackson.databind.ObjectMapper; // ✅ IMPORT
import com.novatech.service_app.entity.SsoConfiguration;
import com.novatech.service_app.repository.SsoConfigurationRepository;
import com.novatech.service_app.service.TenantContext;
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

    // ✅ Create an ObjectMapper to parse JSON
    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * ✅ [FIXED] Get tenant-specific OIDC config
     */
    private SsoConfiguration getOidcConfig() {
        Long tenantId = TenantContext.getTenantId();
        if (tenantId == null) {
            throw new IllegalStateException("OIDC service called without tenant context");
        }

        Optional<SsoConfiguration> configOpt = ssoConfigRepository.findBySsoTypeAndTenantId("OIDC", tenantId);

        if (configOpt.isEmpty()) {
            throw new IllegalStateException("OIDC configuration not found in database for tenant: " + tenantId);
        }
        return configOpt.get();
    }

    /**
     * ✅ Exchange authorization code for access token
     */
    public Map<String, Object> exchangeCodeForToken(String authorizationCode) throws Exception {
        logger.info("=== EXCHANGING OIDC CODE FOR TOKEN ===");

        SsoConfiguration config = getOidcConfig();

        if (config.getTokenEndpoint() == null || config.getTokenEndpoint().isBlank()) {
            throw new IllegalStateException("OIDC token endpoint not configured");
        }

        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        String auth = config.getClientId() + ":" + config.getClientSecret();
        String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes());
        headers.set("Authorization", "Basic " + encodedAuth);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "authorization_code");
        body.add("code", authorizationCode);
        body.add("redirect_uri", config.getRedirectUri());
        body.add("client_id", config.getClientId());

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        logger.info("📤 Sending token request to: {}", config.getTokenEndpoint());

        try {
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

        SsoConfiguration config = getOidcConfig();

        if (config.getUserinfoEndpoint() == null || config.getUserinfoEndpoint().isBlank()) {
            logger.warn("⚠️ UserInfo endpoint not configured, skipping user info fetch");
            return Map.of();
        }

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
            return Map.of();
        }
    }

    /**
     * ✅ [FIXED] Parse ID token (JWT) from token response
     */
    public Map<String, Object> parseIdToken(String idToken) {
        try {
            String[] parts = idToken.split("\\.");
            if (parts.length < 2) { // Allow JWTs without signature, though not ideal
                throw new IllegalArgumentException("Invalid JWT format");
            }

            String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
            logger.info("✅ ID Token payload: {}", payload);

            // ✅ THIS IS THE FIX: Actually parse the JSON payload
            return objectMapper.readValue(payload, new TypeReference<Map<String, Object>>() {});

        } catch (Exception e) {
            logger.error("❌ Error parsing ID token: {}", e.getMessage());
            return Map.of();
        }
    }
}