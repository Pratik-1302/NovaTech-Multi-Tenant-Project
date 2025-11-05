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

    /**
     * Check if a specific SSO type is enabled
     */
    boolean existsBySsoTypeAndEnabledTrue(String ssoType);
}
//working-version