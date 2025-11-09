package com.novatech.service_app.service;

import com.novatech.service_app.entity.SsoConfiguration;
import com.novatech.service_app.entity.Tenant; // ✅ IMPORT
import com.novatech.service_app.repository.SsoConfigurationRepository;
import com.novatech.service_app.repository.TenantRepository; // ✅ IMPORT
import com.novatech.service_app.service.SsoManagementService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureException;
import jakarta.servlet.http.HttpServletRequest; // ✅ IMPORT
import org.slf4j.Logger; // ✅ IMPORT
import org.slf4j.LoggerFactory; // ✅ IMPORT
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder; // ✅ IMPORT
import org.springframework.web.context.request.ServletRequestAttributes; // ✅ IMPORT

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

    private static final Logger logger = LoggerFactory.getLogger(SSOService.class); // ✅ Added Logger

    @Autowired
    private SsoConfigurationRepository ssoConfigRepository;

    @Autowired
    private SsoManagementService ssoManagementService;

    @Autowired
    private TenantRepository tenantRepository; // ✅ INJECT TenantRepository

    // ============================================================
    //                    AUTHORIZATION URL BUILDER (FIXED)
    // ============================================================

    public String getAuthorizationUrl(String ssoType) {
        // ✅ This service MUST be called from a tenant context
        Long tenantId = TenantContext.getTenantId();
        if (tenantId == null) {
            throw new IllegalStateException("SSO login attempted without a tenant context.");
        }

        try {
            // ✅ Use tenant-aware method
            Optional<SsoConfiguration> configOpt = ssoConfigRepository.findBySsoTypeAndTenantId(ssoType.toUpperCase(), tenantId);

            if (configOpt.isEmpty()) {
                throw new IllegalStateException("SSO configuration not found for type: " + ssoType + " and tenant: " + tenantId);
            }

            SsoConfiguration config = configOpt.get();
            if (!config.isEnabled()) {
                throw new IllegalStateException("SSO type " + ssoType + " is not enabled for tenant: " + tenantId);
            }

            if (!ssoManagementService.isConfigValid(config)) {
                throw new IllegalStateException("SSO configuration incomplete or invalid for type: " + ssoType);
            }

            // ===================================================================
            // ✅ START: DYNAMIC REDIRECT URI FIX
            // ===================================================================
            // Generate the tenant-specific callback URL
            String tenantAwareRedirectUri = generateTenantAwareRedirectUri(config.getRedirectUri());
            String encodedRedirect = URLEncoder.encode(tenantAwareRedirectUri, StandardCharsets.UTF_8);
            // ===================================================================
            // ✅ END: DYNAMIC REDIRECT URI FIX
            // ===================================================================

            String ssoUrl;
            switch (ssoType.toUpperCase()) {
                case "JWT":
                    ssoUrl = buildJwtAuthUrl(config, encodedRedirect);
                    break;
                case "OIDC":
                    ssoUrl = buildOidcAuthUrl(config, encodedRedirect);
                    break;
                case "SAML":
                    // SAML config doesn't use the redirect in the auth URL
                    // The IdP is configured with the tenant-aware redirect URL
                    ssoUrl = buildSamlAuthUrl(config);
                    break;
                default:
                    throw new IllegalStateException("Unsupported SSO type: " + ssoType);
            }

            logger.info("🔗 SSO Login URL generated for {} (Tenant {}): {}", ssoType, tenantId, ssoUrl);
            logger.info("📍 Redirect URI set to: {}", tenantAwareRedirectUri);

            return ssoUrl;

        } catch (Exception e) {
            throw new RuntimeException("Failed to build SSO authorization URL: " + e.getMessage(), e);
        }
    }

    /**
     * ✅ NEW: Dynamically builds the tenant-specific redirect URL.
     * Takes "http://localhost:8080/sso/callback"
     * and returns "http://[subdomain].localhost:8080/sso/callback"
     */
    private String generateTenantAwareRedirectUri(String baseRedirectUri) {
        try {
            // Get current tenant ID
            Long tenantId = TenantContext.getTenantId();
            if (tenantId == null) {
                logger.warn("Cannot build tenant-aware URI, no tenantId in context. Returning base URI.");
                return baseRedirectUri;
            }

            // Get tenant subdomain
            Optional<Tenant> tenantOpt = tenantRepository.findById(tenantId);
            if (tenantOpt.isEmpty()) {
                logger.error("Failed to find tenant with ID: {}", tenantId);
                return baseRedirectUri;
            }
            String subdomain = tenantOpt.get().getSubdomain();

            // Get current request to find scheme, server, and port
            HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
            String scheme = request.getScheme(); // http
            int port = request.getServerPort(); // 8080

            // Rebuild the URL
            // We replace "localhost" with "[subdomain].localhost"
            String tenantHost = subdomain + ".localhost";
            String portString = (port == 80 || port == 443) ? "" : ":" + port;

            // Example: http://acme.localhost:8080/sso/callback
            String tenantAwareUrl = scheme + "://" + tenantHost + portString + "/sso/callback";

            return tenantAwareUrl;

        } catch (Exception e) {
            logger.error("Error generating tenant-aware redirect URI: {}", e.getMessage(), e);
            // Fallback to the (likely incorrect) base URI
            return baseRedirectUri;
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

    private String buildSamlAuthUrl(SsoConfiguration config) {
        // For SP-Initiated SAML, we just redirect to the IdP's SSO URL.
        return config.getAuthorizationEndpoint();
    }

    public String getAuthorizationUrl() {
        return getAuthorizationUrl("JWT"); // Default, but should be called with type
    }

    // ============================================================
    //                    JWT TOKEN VERIFICATION (FIXED)
    // ============================================================

    public Map<String, Object> parseJwtToken(String jwtToken) throws Exception {
        Long tenantId = TenantContext.getTenantId();
        if (tenantId == null) {
            throw new IllegalStateException("Cannot parse JWT, no tenant context.");
        }

        Optional<SsoConfiguration> configOpt = ssoConfigRepository.findBySsoTypeAndTenantId("JWT", tenantId);
        if (configOpt.isEmpty()) {
            throw new IllegalStateException("JWT SSO configuration not found in database for tenant: " + tenantId);
        }

        SsoConfiguration config = configOpt.get();
        if (config.getCertificatePath() == null || config.getCertificatePath().isBlank()) {
            throw new IllegalStateException("JWT certificate path not configured for tenant: " + tenantId);
        }

        PublicKey publicKey = loadPublicKeyFromCert(config.getCertificatePath());
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(publicKey)
                    .setAllowedClockSkewSeconds(10)
                    .build()
                    .parseClaimsJws(jwtToken)
                    .getBody();
            logger.info("✅ JWT successfully verified for tenant {}. User claims: {}", tenantId, claims);
            return claims;
        } catch (SignatureException e) {
            throw new IllegalArgumentException("❌ Invalid JWT signature — certificate mismatch for tenant: " + tenantId, e);
        } catch (Exception e) {
            throw new RuntimeException("❌ Error parsing JWT token for tenant: " + tenantId + " - " + e.getMessage(), e);
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
    //                    HELPER METHODS (FIXED)
    // ============================================================

    public Optional<SsoConfiguration> getSsoConfig(String ssoType) {
        Long tenantId = TenantContext.getTenantId();
        if (tenantId == null) {
            return Optional.empty();
        }
        return ssoConfigRepository.findBySsoTypeAndTenantId(ssoType.toUpperCase(), tenantId);
    }

    public boolean isSsoAvailable(String ssoType) {
        Long tenantId = TenantContext.getTenantId();
        if (tenantId == null) {
            return false;
        }
        return ssoConfigRepository.existsBySsoTypeAndEnabledTrueAndTenantId(ssoType.toUpperCase(), tenantId);
    }
}