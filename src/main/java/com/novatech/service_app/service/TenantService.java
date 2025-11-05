package com.novatech.service_app.service;

import com.novatech.service_app.entity.Tenant;
import com.novatech.service_app.entity.User;
import com.novatech.service_app.repository.TenantRepository;
import com.novatech.service_app.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

/**
 * Service for managing tenants.
 */
@Service
public class TenantService {

    @Autowired
    private TenantRepository tenantRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * Create a new tenant (called by Superadmin).
     * This method now calls the main registration method,
     * passing "Admin" as the default full name for the new tenant's admin.
     */
    @Transactional
    public Tenant createTenant(String name, String email, String password, String subdomain) {

        // This now calls our new, more detailed registration method.
        // This keeps our code DRY (Don't Repeat Yourself).
        return registerNewTenantAndAdmin(
                name,        // orgName
                email,       // adminEmail
                password,    // adminPassword
                subdomain,
                "Admin"      // default fullName for the admin
        );
    }

    // ============================================================
    //         START: NEW SELF-SERVICE REGISTRATION METHOD
    // ============================================================
    /**
     * Handles public, self-service registration (Your New Feature).
     * Creates a new Tenant AND their Admin User in one safe transaction.
     *
     * @param orgName       The new company's name (e.g., "My Company")
     * @param adminEmail    The email for the new admin (e.g., "pratik@mycompany.com")
     * @param adminPassword The raw password for the new admin
     * @param subdomain     The desired subdomain (e.g., "mycompany")
     * @param adminName     The full name of the new admin (e.g., "Pratik")
     * @return The newly created Tenant
     */
    @Transactional
    public Tenant registerNewTenantAndAdmin(String orgName, String adminEmail, String adminPassword, String subdomain, String adminName) {

        // --- 1. VALIDATION ---
        // Check if the subdomain is taken
        if (tenantRepository.existsBySubdomain(subdomain)) {
            throw new RuntimeException("Subdomain " + subdomain + " already taken");
        }
        // Check if the admin's email is already in use
        if (userRepository.existsByEmail(adminEmail)) {
            throw new RuntimeException("User with email " + adminEmail + " already exists");
        }

        // --- 2. STEP 1: CREATE THE TENANT ---
        Tenant tenant = new Tenant();
        tenant.setName(orgName);
        tenant.setEmail(adminEmail); // Use admin email as the tenant contact
        tenant.setSubdomain(subdomain);

        Tenant savedTenant = tenantRepository.save(tenant);

        // --- 3. STEP 2: CREATE THE ADMIN USER ---
        User adminUser = new User();
        adminUser.setFullName(adminName); // Use the name from the form
        adminUser.setEmail(adminEmail);
        adminUser.setPasswordHash(passwordEncoder.encode(adminPassword));
        adminUser.setRole("ROLE_ADMIN"); // Set them as the admin
        adminUser.setTenant(savedTenant); // Link them to the new tenant

        userRepository.save(adminUser);

        return savedTenant;
    }
    // ============================================================
    //         END: NEW SELF-SERVICE REGISTRATION METHOD
    // ============================================================


    /**
     * Get all tenants (for Superadmin dashboard).
     */
    public List<Tenant> getAllTenants() {
        return tenantRepository.findAll();
    }

    /**
     * Get tenant by ID.
     */
    public Optional<Tenant> getTenantById(Long id) {
        return tenantRepository.findById(id);
    }

    /**
     * Get tenant by subdomain (used by TenantFilter).
     */
    public Optional<Tenant> getTenantBySubdomain(String subdomain) {
        return tenantRepository.findBySubdomain(subdomain);
    }

    /**
     * Get tenant by email (used for tenant-admin login).
     */
    public Optional<Tenant> getTenantByEmail(String email) {
        return tenantRepository.findByEmail(email);
    }

    /**
     * Update tenant details.
     */
    @Transactional
    public Tenant updateTenant(Long id, String name, String email, String subdomain) {
        Tenant tenant = tenantRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Tenant not found"));

        tenant.setName(name);
        tenant.setEmail(email);
        tenant.setSubdomain(subdomain);

        return tenantRepository.save(tenant);
    }

    /**
     * Delete tenant.
     */
    public void deleteTenant(Long id) {
        // Note: You may want to add logic here to delete all users associated
        // with this tenant *before* deleting the tenant itself.
        // For now, it just deletes the tenant.
        tenantRepository.deleteById(id);
    }
}