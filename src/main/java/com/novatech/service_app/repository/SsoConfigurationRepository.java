package com.novatech.service_app.repository;

import com.novatech.service_app.entity.SsoConfiguration;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * ✅ TENANT-AWARE SSO Configuration Repository
 * All methods now include tenant_id filtering for proper isolation
 */
@Repository
public interface SsoConfigurationRepository extends JpaRepository<SsoConfiguration, Long> {

    /**
     * Legacy method - should be avoided in favor of tenant-aware version
     * @deprecated Use findBySsoTypeAndTenantId instead
     */
    @Deprecated
    Optional<SsoConfiguration> findBySsoType(String ssoType);

    /**
     * Legacy method - should be avoided in favor of tenant-aware version
     * @deprecated Use findByEnabledTrueAndTenantId instead
     */
    @Deprecated
    List<SsoConfiguration> findByEnabledTrue();

    /**
     * Legacy method - should be avoided in favor of tenant-aware version
     * @deprecated Use existsBySsoTypeAndEnabledTrueAndTenantId instead
     */
    @Deprecated
    boolean existsBySsoTypeAndEnabledTrue(String ssoType);

    // ============================================================
    //              ✅ TENANT-AWARE METHODS (PRIMARY)
    // ============================================================

    /**
     * Find SSO config by type for a specific tenant
     * PRIMARY METHOD - Use this instead of findBySsoType
     */
    Optional<SsoConfiguration> findBySsoTypeAndTenantId(String ssoType, Long tenantId);

    /**
     * Find all enabled SSO configurations for a specific tenant
     * PRIMARY METHOD - Use this instead of findByEnabledTrue
     */
    List<SsoConfiguration> findByEnabledTrueAndTenantId(Long tenantId);

    /**
     * Check if a specific SSO type is enabled for a tenant
     * PRIMARY METHOD - Use this instead of existsBySsoTypeAndEnabledTrue
     */
    boolean existsBySsoTypeAndEnabledTrueAndTenantId(String ssoType, Long tenantId);

    /**
     * Find all SSO configurations for a specific tenant (all types, enabled or not)
     */
    List<SsoConfiguration> findByTenantId(Long tenantId);

    /**
     * Check if SSO type exists for a tenant (enabled or not)
     */
    boolean existsBySsoTypeAndTenantId(String ssoType, Long tenantId);
}