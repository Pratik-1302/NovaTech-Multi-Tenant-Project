package com.novatech.service_app.repository;

import com.novatech.service_app.entity.SsoConfiguration;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface SsoConfigurationRepository extends JpaRepository<SsoConfiguration, Long> {

    /**
     * Find SSO config by type (JWT, OIDC, SAML)
     */
    Optional<SsoConfiguration> findBySsoType(String ssoType);

    /**
     * Find all enabled SSO configurations
     */
    List<SsoConfiguration> findByEnabledTrue();

    // ✅ Should be present (line 36)
    Optional<SsoConfiguration> findBySsoTypeAndTenantId(String ssoType, Long tenantId);

    // ✅ Should be present (line 41)
    List<SsoConfiguration> findByEnabledTrueAndTenantId(Long tenantId);

    // ✅ Should be present (line 46)
    boolean existsBySsoTypeAndEnabledTrueAndTenantId(String ssoType, Long tenantId);

    // ✅ Should be present (line 51)
    List<SsoConfiguration> findByTenantId(Long tenantId);

    // ✅ Should be present (line 56)
    boolean existsBySsoTypeAndTenantId(String ssoType, Long tenantId);

    /**
     * Check if a specific SSO type is enabled
     */
    boolean existsBySsoTypeAndEnabledTrue(String ssoType);
}
//working-version