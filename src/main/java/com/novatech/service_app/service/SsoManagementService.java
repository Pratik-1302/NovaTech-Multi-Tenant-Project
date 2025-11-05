package com.novatech.service_app.service;

import com.novatech.service_app.entity.SsoConfiguration;
import com.novatech.service_app.repository.SsoConfigurationRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
public class SsoManagementService {

    @Autowired
    private SsoConfigurationRepository ssoConfigRepository;

    // ... (getAllConfigurations, getConfigByType, getEnabledConfigurations, isSsoTypeEnabled, isJwtEnabled, isOidcEnabled, isSamlEnabled, saveOrUpdateConfig, toggleSsoEnabled, deleteConfigByType methods are all unchanged) ...

    public List<SsoConfiguration> getAllConfigurations() {
        return ssoConfigRepository.findAll();
    }

    public Optional<SsoConfiguration> getConfigByType(String ssoType) {
        return ssoConfigRepository.findBySsoType(ssoType.toUpperCase());
    }

    public List<SsoConfiguration> getEnabledConfigurations() {
        return ssoConfigRepository.findByEnabledTrue();
    }

    public boolean isSsoTypeEnabled(String ssoType) {
        return ssoConfigRepository.existsBySsoTypeAndEnabledTrue(ssoType.toUpperCase());
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

    @Transactional
    public SsoConfiguration saveOrUpdateConfig(SsoConfiguration config) {
        if (config.getSsoType() == null || config.getSsoType().isBlank()) {
            throw new IllegalArgumentException("SSO type cannot be null or empty");
        }
        config.setSsoType(config.getSsoType().toUpperCase());
        Optional<SsoConfiguration> existingConfig = ssoConfigRepository.findBySsoType(config.getSsoType());
        if (existingConfig.isPresent()) {
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
            System.out.println("✅ Updated existing SSO config: " + config.getSsoType());
            return ssoConfigRepository.save(existing);
        } else {
            System.out.println("✅ Created new SSO config: " + config.getSsoType());
            return ssoConfigRepository.save(config);
        }
    }

    @Transactional
    public boolean toggleSsoEnabled(String ssoType, boolean enabled) {
        Optional<SsoConfiguration> config = ssoConfigRepository.findBySsoType(ssoType.toUpperCase());
        if (config.isPresent()) {
            SsoConfiguration ssoConfig = config.get();
            ssoConfig.setEnabled(enabled);
            ssoConfigRepository.save(ssoConfig);
            System.out.println("✅ SSO " + ssoType + " enabled status: " + enabled);
            return true;
        }
        System.err.println("❌ SSO config not found for type: " + ssoType);
        return false;
    }

    @Transactional
    public boolean deleteConfigByType(String ssoType) {
        Optional<SsoConfiguration> config = ssoConfigRepository.findBySsoType(ssoType.toUpperCase());
        if (config.isPresent()) {
            ssoConfigRepository.delete(config.get());
            System.out.println("✅ Deleted SSO config: " + ssoType);
            return true;
        }
        System.err.println("❌ SSO config not found for deletion: " + ssoType);
        return false;
    }

    // ============================================================
    //                    VALIDATION HELPERS (UPDATED)
    // ============================================================

    /**
     * Validate if SSO config has all required fields
     */
    public boolean isConfigValid(SsoConfiguration config) {
        if (config == null) return false;
        // Check required fields based on SSO type
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

            // ✅ UPDATED SAML CASE
            case "SAML":
                // SAML requires: SSO URL, Entity ID (Issuer), Certificate, and ACS URL (Redirect URI)
                // The redirectUri is now hardcoded by the controller, so this validation is still correct.
                return config.getAuthorizationEndpoint() != null && !config.getAuthorizationEndpoint().isBlank()
                        && config.getIssuer() != null && !config.getIssuer().isBlank()
                        && config.getCertificatePath() != null && !config.getCertificatePath().isBlank()
                        && config.getRedirectUri() != null && !config.getRedirectUri().isBlank();

            default:
                return false;
        }
    }
}