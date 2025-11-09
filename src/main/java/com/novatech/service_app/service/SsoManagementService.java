package com.novatech.service_app.service;

import com.novatech.service_app.entity.SsoConfiguration;
import com.novatech.service_app.entity.Tenant;
import com.novatech.service_app.repository.SsoConfigurationRepository;
import com.novatech.service_app.repository.TenantRepository;
import com.novatech.service_app.service.TenantContext; // ✅ Includes TenantContext
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections; // ✅ Includes Collections
import java.util.List;
import java.util.Optional;

/**
 * ✅ [FIXED] TENANT-ISOLATED SSO Management Service
 * Now strictly adheres to TenantContext without fallbacks.
 */
@Service
public class SsoManagementService {

    private static final Logger logger = LoggerFactory.getLogger(SsoManagementService.class);

    @Autowired
    private SsoConfigurationRepository ssoConfigRepository;

    @Autowired
    private TenantRepository tenantRepository;

    // ============================================================
    //                    TENANT-AWARE HELPERS
    // ============================================================

    /**
     * ✅ [REMOVED] Fallback logic removed.
     * This service is now strictly tenant-aware.
     */
    private Long getResolvedTenantId() {
        return TenantContext.getTenantId(); // Can return null
    }

    // ============================================================
    //                    GET METHODS (FIXED)
    // ============================================================

    public Optional<SsoConfiguration> getConfigByType(String ssoType) {
        final Long tenantId = getResolvedTenantId();
        if (tenantId == null) {
            logger.warn("No tenant context, cannot get SSO config");
            return Optional.empty();
        }
        return ssoConfigRepository.findBySsoTypeAndTenantId(ssoType.toUpperCase(), tenantId);
    }

    public List<SsoConfiguration> getEnabledConfigurations() {
        final Long tenantId = getResolvedTenantId();
        if (tenantId == null) {
            logger.warn("No tenant context, cannot get enabled SSO configs");
            return Collections.emptyList();
        }
        return ssoConfigRepository.findByEnabledTrueAndTenantId(tenantId);
    }

    public boolean isSsoTypeEnabled(String ssoType) {
        final Long tenantId = getResolvedTenantId();
        if (tenantId == null) {
            return false; // No tenant, so SSO is not enabled
        }
        return ssoConfigRepository.existsBySsoTypeAndEnabledTrueAndTenantId(ssoType.toUpperCase(), tenantId);
    }

    public boolean isJwtEnabled() {
        return isSsoTypeEnabled("JWT");
    }

    public boolean isOidcEnabled() {
        return isSsoTypeEnabled("OIDC");
    }

    public boolean isSamlEnabled() {
        return isSsoTypeEnabled("SAML");
    }

    // ============================================================
    //                    SAVE / UPDATE (FIXED)
    // ============================================================

    @Transactional
    public SsoConfiguration saveOrUpdateConfig(SsoConfiguration config) {
        final Long tenantId = getResolvedTenantId();

        // This should be called from AdminController, which MUST have a tenant context
        if (tenantId == null) {
            throw new IllegalStateException("Cannot save SSO config without a valid tenant context");
        }

        if (config.getSsoType() == null || config.getSsoType().isBlank()) {
            throw new IllegalArgumentException("SSO type cannot be null or empty");
        }

        config.setSsoType(config.getSsoType().toUpperCase());

        Optional<SsoConfiguration> existingConfig =
                ssoConfigRepository.findBySsoTypeAndTenantId(config.getSsoType(), tenantId);

        if (existingConfig.isPresent()) {
            // ✅ Update existing
            SsoConfiguration existing = existingConfig.get();
            existing.setProviderName(config.getProviderName());
            existing.setClientId(config.getClientId());
            existing.setClientSecret(config.getClientSecret());
            existing.setAuthorizationEndpoint(config.getAuthorizationEndpoint());
            existing.setTokenEndpoint(config.getTokenEndpoint());
            existing.setUserinfoEndpoint(config.getUserinfoEndpoint());
            existing.setRedirectUri(config.getRedirectUri());
            existing.setCertificatePath(config.getCertificatePath());
            existing.setDomain(config.getDomain());
            existing.setIssuer(config.getIssuer());
            existing.setScopes(config.getScopes());
            existing.setEnabled(config.isEnabled());

            logger.info("✅ Updated SSO config [{}] for tenant [{}]", config.getSsoType(), tenantId);
            return ssoConfigRepository.save(existing);
        } else {
            // ✅ Create new config
            Tenant tenant = tenantRepository.findById(tenantId)
                    .orElseThrow(() -> new RuntimeException("Tenant not found: " + tenantId));

            // This is the call you flagged. It is correct.
            config.setTenant(tenant);

            logger.info("✅ Created new SSO config [{}] for tenant [{}]", config.getSsoType(), tenantId);
            return ssoConfigRepository.save(config);
        }
    }

    // ============================================================
    //                    TOGGLE ENABLED (FIXED)
    // ============================================================

    @Transactional
    public boolean toggleSsoEnabled(String ssoType, boolean enabled) {
        final Long tenantId = getResolvedTenantId();
        if (tenantId == null) {
            logger.error("❌ No tenant context, cannot toggle SSO");
            return false;
        }

        Optional<SsoConfiguration> config =
                ssoConfigRepository.findBySsoTypeAndTenantId(ssoType.toUpperCase(), tenantId);

        if (config.isPresent()) {
            SsoConfiguration ssoConfig = config.get();
            ssoConfig.setEnabled(enabled);
            ssoConfigRepository.save(ssoConfig);
            logger.info("✅ Toggled {} SSO to {} for tenant {}", ssoType, enabled, tenantId);
            return true;
        }

        logger.error("❌ No SSO config found for {} and tenant {}", ssoType, tenantId);
        return false;
    }

    // ============================================================
    //                    DELETE CONFIG (FIXED)
    // ============================================================

    @Transactional
    public boolean deleteConfigByType(String ssoType) {
        final Long tenantId = getResolvedTenantId();
        if (tenantId == null) {
            logger.error("❌ No tenant context, cannot delete SSO config");
            return false;
        }

        Optional<SsoConfiguration> config =
                ssoConfigRepository.findBySsoTypeAndTenantId(ssoType.toUpperCase(), tenantId);

        if (config.isPresent()) {
            ssoConfigRepository.delete(config.get());
            logger.info("✅ Deleted SSO config [{}] for tenant [{}]", ssoType, tenantId);
            return true;
        }

        logger.warn("❌ Could not find SSO config [{}] for tenant [{}]", ssoType, tenantId);
        return false;
    }

    // ============================================================
    //                    VALIDATION (Unchanged)
    // ============================================================

    public boolean isConfigValid(SsoConfiguration config) {
        if (config == null) return false;

        switch (config.getSsoType().toUpperCase()) {
            case "JWT":
                return config.getClientId() != null && !config.getClientId().isBlank()
                        && config.getClientSecret() != null && !config.getClientSecret().isBlank()
                        && config.getAuthorizationEndpoint() != null && !config.getAuthorizationEndpoint().isBlank()
                        && config.getRedirectUri() != null && !config.getRedirectUri().isBlank()
                        && config.getCertificatePath() != null && !config.getCertificatePath().isBlank();

            case "OIDC":
                return config.getClientId() != null && !config.getClientId().isBlank()
                        && config.getClientSecret() != null && !config.getClientSecret().isBlank()
                        && config.getAuthorizationEndpoint() != null && !config.getAuthorizationEndpoint().isBlank()
                        && config.getTokenEndpoint() != null && !config.getTokenEndpoint().isBlank()
                        && config.getRedirectUri() != null && !config.getRedirectUri().isBlank();

            case "SAML":
                return config.getAuthorizationEndpoint() != null && !config.getAuthorizationEndpoint().isBlank()
                        && config.getIssuer() != null && !config.getIssuer().isBlank()
                        && config.getCertificatePath() != null && !config.getCertificatePath().isBlank()
                        && config.getRedirectUri() != null && !config.getRedirectUri().isBlank();

            default:
                return false;
        }
    }

    // ============================================================
    //                    ADMIN METHODS (Unchanged)
    // ============================================================

    public List<SsoConfiguration> getAllConfigurationsForTenant(Long tenantId) {
        // This one takes an explicit tenantId, so it's fine
        return ssoConfigRepository.findByTenantId(tenantId);
    }
}