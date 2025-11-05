package com.novatech.service_app.repository;

import com.novatech.service_app.entity.Tenant;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Repository for managing Tenant entities.
 */
@Repository
public interface TenantRepository extends JpaRepository<Tenant, Long> {

    /**
     * Find tenant by subdomain (used by TenantFilter).
     */
    Optional<Tenant> findBySubdomain(String subdomain);

    /**
     * Find tenant by email (used for tenant-admin login).
     */
    Optional<Tenant> findByEmail(String email);

    /**
     * Check if subdomain already exists (validation).
     */
    boolean existsBySubdomain(String subdomain);

    /**
     * Check if email already exists (validation).
     */
    boolean existsByEmail(String email);
}