package com.novatech.service_app.repository;

import com.novatech.service_app.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;
import java.util.Optional;

/**
 * Repository interface for managing User entities.
 * Now includes tenant-aware queries.
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    /**
     * Find user by email (used for login).
     */
    Optional<User> findByEmail(String email);

    /**
     * Check if a user exists by email.
     */
    boolean existsByEmail(String email);

    /**
     * Find all users by role.
     */
    List<User> findByRole(String role);

    /**
     * Find all users sorted by ID.
     */
    List<User> findAllByOrderByIdAsc();

    // ============================================================
    // ✅ NEW: Tenant-aware queries
    // ============================================================

    /**
     * Find all users belonging to a specific tenant.
     */
    List<User> findByTenantId(Long tenantId);

    /**
     * Find user by email within a specific tenant.
     */
    Optional<User> findByEmailAndTenantId(String email, Long tenantId);

    /**
     * Check if email exists within a specific tenant.
     */
    boolean existsByEmailAndTenantId(String email, Long tenantId);

    /**
     * Count users in a tenant.
     */
    long countByTenantId(Long tenantId);
}