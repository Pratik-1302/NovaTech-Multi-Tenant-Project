package com.novatech.service_app.service;

import com.novatech.service_app.service.TenantContext; // ⬅️ ADD THIS LINEimport com.novatech.service_app.entity.Tenant;
import com.novatech.service_app.entity.User;
import com.novatech.service_app.entity.Tenant;
import com.novatech.service_app.repository.TenantRepository;
import com.novatech.service_app.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

/**
 * ✅ [SIMPLIFIED] Multi-tenant authentication service
 * Handles: Superadmin, and (Tenant-admin + End-user) from the USERS table
 */
@Service
public class UserService implements UserDetailsService {

    private static final Logger logger = LoggerFactory.getLogger(UserService.class);

    private final UserRepository userRepository;
    private final TenantRepository tenantRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${app.superadmin.username:superadmin@novatech.com}")
    private String superadminUsername;

    @Value("${app.superadmin.password:admin123}")
    private String superadminPassword;

    @Autowired
    public UserService(UserRepository userRepository,
                       TenantRepository tenantRepository,
                       PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.tenantRepository = tenantRepository;
        this.passwordEncoder = passwordEncoder;
    }

    // ======================================================
    //          SPRING SECURITY AUTHENTICATION
    // ======================================================

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        logger.debug("🔐 loadUserByUsername called for: {}", email);
        logger.debug("🔍 Current TenantContext: {}", TenantContext.getTenantId());

        // ============================================================
        // CASE 1: SUPERADMIN LOGIN (no tenant context, at localhost)
        // ============================================================
        if (TenantContext.isSuperAdminContext() && email.equals(superadminUsername)) {
            logger.info("✅ Superadmin authentication for: {}", email);

            return new CustomUserDetails(
                    email,
                    passwordEncoder.encode(superadminPassword), // Hardcoded password
                    "ROLE_SUPERADMIN",
                    0L,
                    null,
                    "SUPERADMIN",
                    "Super Administrator"
            );
        }

        // ============================================================
        // [NEW SIMPLIFIED LOGIC]
        // CASE 2: TENANT LOGIN (ADMIN OR USER)
        // We NO LONGER check the tenants table for passwords.
        // All users, including admins, must be in the 'users' table.
        // ============================================================
        Long tenantId = TenantContext.getTenantId();
        if (tenantId == null) {
            // This should not happen if not superadmin, as TenantFilter should have caught it
            logger.warn("❌ Authentication failed: No Tenant ID found for email: {}", email);
            throw new UsernameNotFoundException("User not found: " + email);
        }

        Optional<User> userOpt = userRepository.findByEmailAndTenantId(email, tenantId);

        if (userOpt.isPresent()) {
            User user = userOpt.get();
            // Determine userType string based on role for CustomUserDetails
            String userType = "END_USER";
            if (user.getRole().equals("ROLE_ADMIN")) {
                userType = "TENANT_ADMIN";
            }

            logger.info("✅ {} authentication for: {} (Tenant ID: {})",
                    userType, email, tenantId);

            // We use the same CustomUserDetails for both
            return new CustomUserDetails(
                    user.getEmail(),
                    user.getPasswordHash(), // This password_hash WORKS (from signup form)
                    user.getRole(),
                    user.getId(),
                    tenantId,
                    userType,
                    user.getFullName()
            );
        }

        // ============================================================
        // CASE 3: NO MATCH - Authentication Failed
        // ============================================================
        logger.warn("❌ Authentication failed for: {} (Tenant: {})", email, tenantId);
        throw new UsernameNotFoundException("User not found: " + email);
    }


    // ======================================================
    //          USER MANAGEMENT (Tenant-Aware)
    //          [ALL METHODS BELOW ARE UNCHANGED]
    // ======================================================

    @Transactional(readOnly = true)
    public User findByEmail(String email) {
        Long tenantId = TenantContext.getTenantId();

        if (tenantId != null) {
            return userRepository.findByEmailAndTenantId(email, tenantId).orElse(null);
        }

        return userRepository.findByEmail(email).orElse(null);
    }

    @Transactional(readOnly = true)
    public List<User> getAllUsers() {
        Long tenantId = TenantContext.getTenantId();

        if (tenantId != null) {
            // Tenant-admin: only their users
            logger.debug("🔍 Getting users for tenant: {}", tenantId);
            return userRepository.findByTenantId(tenantId);
        }

        // Superadmin: all users
        logger.debug("🔍 Getting all users (Superadmin)");
        return userRepository.findAllByOrderByIdAsc();
    }

    @Transactional(readOnly = true)
    public boolean emailExists(String email) {
        Long tenantId = TenantContext.getTenantId();

        if (tenantId != null) {
            return userRepository.existsByEmailAndTenantId(email, tenantId);
        }

        return userRepository.existsByEmail(email);
    }

    /**
     * This is the method used by the Signup Form.
     * We know this works perfectly.
     */
    @Transactional
    public User registerUser(String fullName, String email, String password) {
        Long tenantId = TenantContext.getTenantId();

        logger.info("📝 Registering user: {} (Tenant: {})", email, tenantId);

        if (emailExists(email)) {
            throw new RuntimeException("User already exists with email: " + email);
        }

        User user = new User();
        user.setFullName(fullName);
        user.setEmail(email);
        user.setPasswordHash(passwordEncoder.encode(password));
        user.setRole("ROLE_USER");

        // Set tenant if in tenant context
        if (tenantId != null) {
            Tenant tenant = tenantRepository.findById(tenantId)
                    .orElseThrow(() -> new RuntimeException("Tenant not found"));
            user.setTenant(tenant);
            logger.info("✅ User registered under tenant: {}", tenant.getName());
        }

        return userRepository.save(user);
    }

    @Transactional
    public void createUserWithPassword(User user, String password) {
        Long tenantId = TenantContext.getTenantId();

        if (emailExists(user.getEmail())) {
            throw new RuntimeException("User already exists with this email!");
        }

        user.setPasswordHash(passwordEncoder.encode(password));

        if (user.getRole() == null || user.getRole().isEmpty()) {
            user.setRole("ROLE_USER");
        }

        // Set tenant if in tenant context
        if (tenantId != null && user.getTenant() == null) {
            Tenant tenant = tenantRepository.findById(tenantId)
                    .orElseThrow(() -> new RuntimeException("Tenant not found"));
            user.setTenant(tenant);
        }

        userRepository.save(user);
    }

    @Transactional
    public void updateUserDetails(Long id, String fullName, String password, String role) {
        User targetUser = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found with ID: " + id));

        // Security checks
        if (targetUser.getRole().equals("ROLE_SUPERADMIN")) {
            throw new AccessDeniedException("Access Denied: The Super Admin account cannot be modified.");
        }

        if (role.equals("ROLE_SUPERADMIN")) {
            throw new AccessDeniedException("Access Denied: A new Super Admin cannot be created.");
        }

        // Tenant isolation check
        Long tenantId = TenantContext.getTenantId();
        if (tenantId != null) {
            if (targetUser.getTenant() == null || !targetUser.getTenant().getId().equals(tenantId)) {
                throw new AccessDeniedException("Access Denied: Cannot modify users from other tenants.");
            }
        }

        targetUser.setFullName(fullName);
        targetUser.setRole(role);

        if (password != null && !password.isEmpty()) {
            targetUser.setPasswordHash(passwordEncoder.encode(password));
        }

        userRepository.save(targetUser);
    }

    @Transactional
    public void deleteUserById(Long id) {
        User targetUser = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found with ID: " + id));

        // Security checks
        if (targetUser.getRole().equals("ROLE_SUPERADMIN")) {
            throw new AccessDeniedException("Access Denied: The Super Admin account cannot be deleted.");
        }

        // Tenant isolation check
        Long tenantId = TenantContext.getTenantId();
        if (tenantId != null) {
            if (targetUser.getTenant() == null || !targetUser.getTenant().getId().equals(tenantId)) {
                throw new AccessDeniedException("Access Denied: Cannot delete users from other tenants.");
            }
        }

        userRepository.deleteById(id);
    }

    // ======================================================
    //          UTILITY METHODS
    // ======================================================

    @Transactional(readOnly = true)
    public long getUserCount() {
        Long tenantId = TenantContext.getTenantId();

        if (tenantId != null) {
            return userRepository.countByTenantId(tenantId);
        }

        return userRepository.count();
    }
}