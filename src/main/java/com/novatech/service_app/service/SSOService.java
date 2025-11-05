package com.novatech.service_app.service;

import com.novatech.service_app.entity.SsoConfiguration;
import com.novatech.service_app.repository.SsoConfigurationRepository;
import com.novatech.service_app.service.SsoManagementService; // ✅ IMPORT SsoManagementService
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.Optional;

@Service
public class SSOService {

    @Autowired
    private SsoConfigurationRepository ssoConfigRepository;

    // ✅ AUTOWIRE SsoManagementService to use its validation logic
    @Autowired
    private SsoManagementService ssoManagementService;

    // ============================================================
    //                    AUTHORIZATION URL BUILDER
    // ============================================================

    public String getAuthorizationUrl(String ssoType) {
        try {
            Optional<SsoConfiguration> configOpt = ssoConfigRepository.findBySsoType(ssoType.toUpperCase());
            if (configOpt.isEmpty()) {
                throw new IllegalStateException("SSO configuration not found for type: " + ssoType);
            }

            SsoConfiguration config = configOpt.get();
            if (!config.isEnabled()) {
                throw new IllegalStateException("SSO type " + ssoType + " is not enabled");
            }

            // ✅ FIXED VALIDATION: Use the SsoManagementService to validate
            // This now correctly validates all 3 SSO types.
            if (!ssoManagementService.isConfigValid(config)) {
                throw new IllegalStateException("SSO configuration incomplete or invalid for type: " + ssoType);
            }

            // Build authorization URL based on SSO type
            String ssoUrl;
            String encodedRedirect = URLEncoder.encode(config.getRedirectUri(), StandardCharsets.UTF_8);

            switch (ssoType.toUpperCase()) {
                case "JWT":
                    ssoUrl = buildJwtAuthUrl(config, encodedRedirect);
                    break;

                case "OIDC":
                    ssoUrl = buildOidcAuthUrl(config, encodedRedirect);
                    break;

                case "SAML":
                    ssoUrl = buildSamlAuthUrl(config, encodedRedirect);
                    break;

                default:
                    throw new IllegalStateException("Unsupported SSO type: " + ssoType);
            }

            System.out.println("🔗 SSO Login URL generated for " + ssoType + ": " + ssoUrl);
            System.out.println("📍 Redirect URI: " + config.getRedirectUri());

            return ssoUrl;

        } catch (Exception e) {
            throw new RuntimeException("Failed to build SSO authorization URL: " + e.getMessage(), e);
        }
    }

    private String buildJwtAuthUrl(SsoConfiguration config, String encodedRedirect) {
        return config.getAuthorizationEndpoint()
                + "?client_id=" + config.getClientId()
                + "&redirect_uri=" + encodedRedirect
                + "&response_type=id_token"
                + "&scope=openid email profile"
                + "&nonce=" + System.currentTimeMillis();
    }

    private String buildOidcAuthUrl(SsoConfiguration config, String encodedRedirect) {
        String scopes = config.getScopes() != null && !config.getScopes().isBlank()
                ? config.getScopes()
                : "openid profile email";
        String encodedScopes = URLEncoder.encode(scopes, StandardCharsets.UTF_8);

        return config.getAuthorizationEndpoint()
                + "?client_id=" + config.getClientId()
                + "&redirect_uri=" + encodedRedirect
                + "&response_type=code"
                + "&scope=" + encodedScopes
                + "&state=" + System.currentTimeMillis()
                + "&nonce=" + System.currentTimeMillis();
    }

    /**
     * ✅ FIXED: Build SAML authorization URL
     */
    private String buildSamlAuthUrl(SsoConfiguration config, String encodedRedirect) {
        // For SP-Initiated SAML, we just redirect to the IdP's SSO URL.
        return config.getAuthorizationEndpoint();
    }

    public String getAuthorizationUrl() {
        return getAuthorizationUrl("JWT");
    }

    // ============================================================
    //                    JWT TOKEN VERIFICATION
    // ============================================================

    public Map<String, Object> parseJwtToken(String jwtToken) throws Exception {
        Optional<SsoConfiguration> configOpt = ssoConfigRepository.findBySsoType("JWT");
        if (configOpt.isEmpty()) {
            throw new IllegalStateException("JWT SSO configuration not found in database");
        }
        SsoConfiguration config = configOpt.get();
        if (config.getCertificatePath() == null || config.getCertificatePath().isBlank()) {
            throw new IllegalStateException("JWT certificate path not configured");
        }
        PublicKey publicKey = loadPublicKeyFromCert(config.getCertificatePath());
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(publicKey)
                    .setAllowedClockSkewSeconds(10)
                    .build()
                    .parseClaimsJws(jwtToken)
                    .getBody();
            System.out.println("✅ JWT successfully verified. User claims: " + claims);
            return claims;
        } catch (SignatureException e) {
            throw new IllegalArgumentException("❌ Invalid JWT signature — certificate mismatch.", e);
        } catch (Exception e) {
            throw new RuntimeException("❌ Error parsing JWT token: " + e.getMessage(), e);
        }
    }

    private PublicKey loadPublicKeyFromCert(String certPath) throws Exception {
        try {
            String cleanPath = certPath.replace("classpath:", "");
            ClassPathResource resource = new ClassPathResource(cleanPath);
            if (!resource.exists()) {
                throw new IllegalArgumentException("Certificate file not found in classpath: " + cleanPath);
            }
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            try (InputStream in = resource.getInputStream()) {
                X509Certificate cert = (X509Certificate) factory.generateCertificate(in);
                return cert.getPublicKey();
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to load certificate from: " + certPath + " - " + e.getMessage(), e);
        }
    }

    // ============================================================
    //                    HELPER METHODS
    // ============================================================

    public Optional<SsoConfiguration> getSsoConfig(String ssoType) {
        return ssoConfigRepository.findBySsoType(ssoType.toUpperCase());
    }

    public boolean isSsoAvailable(String ssoType) {
        Optional<SsoConfiguration> config = ssoConfigRepository.findBySsoType(ssoType.toUpperCase());
        return config.isPresent() && config.get().isEnabled();
    }
}