package com.novatech.service_app.controller;

import com.novatech.service_app.entity.Tenant;
import com.novatech.service_app.entity.User;
import com.novatech.service_app.repository.TenantRepository;
import com.novatech.service_app.repository.UserRepository;
import com.novatech.service_app.service.TenantService;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Superadmin Dashboard Controller
 * Handles tenant management and system-wide operations
 */
@Controller
@RequestMapping("/superadmin")
@PreAuthorize("hasRole('SUPERADMIN')")
public class SuperAdminController {

    private static final Logger logger = LoggerFactory.getLogger(SuperAdminController.class);

    @Autowired
    private TenantService tenantService;

    @Autowired
    private TenantRepository tenantRepository;

    @Autowired
    private UserRepository userRepository;

    // ============================================================
    //                    DASHBOARD PAGE (Unchanged)
    // ============================================================

    @GetMapping("/dashboard")
    public String dashboard(Model model, HttpSession session) {
        logger.info("=== SUPERADMIN DASHBOARD ACCESSED ===");

        String displayName = (String) session.getAttribute("displayName");
        model.addAttribute("displayName", displayName != null ? displayName : "Super Administrator");

        // Fetch all tenants
        List<Tenant> tenants = tenantService.getAllTenants();
        model.addAttribute("tenants", tenants);

        // Dashboard statistics
        model.addAttribute("totalTenants", tenants.size());
        model.addAttribute("totalUsers", userRepository.count());

        logger.info("Dashboard loaded - Tenants: {}, Users: {}", tenants.size(), userRepository.count());

        return "superadmin-dashboard";
    }

    // ============================================================
    //                    CREATE TENANT (AJAX) (FIXED)
    // ============================================================

    @PostMapping("/tenants/create")
    @ResponseBody
    public ResponseEntity<?> createTenant(@RequestBody Map<String, String> payload) {
        try {
            String name = payload.get("name");
            String email = payload.get("email");
            String password = payload.get("password");
            String subdomain = payload.get("subdomain");

            logger.info("Creating tenant: {} (subdomain: {})", name, subdomain);

            // Validation checks
            // ▼▼▼ THIS LINE WAS CHANGED ▼▼▼
            if (userRepository.existsByEmail(email)) { // Check users table, not tenants
                return ResponseEntity.badRequest().body(Map.of("error", "Email already exists"));
            }
            // ▲▲▲ THIS LINE WAS CHANGED ▲▲▲

            if (tenantRepository.existsBySubdomain(subdomain)) {
                return ResponseEntity.badRequest().body(Map.of("error", "Subdomain already taken"));
            }

            // Create tenant (This now also creates the admin user, thanks to TenantService)
            Tenant tenant = tenantService.createTenant(name, email, password, subdomain);

            logger.info("✅ Tenant created successfully: {}", tenant.getId());

            Map<String, Object> tenantData = new HashMap<>();
            tenantData.put("id", tenant.getId());
            tenantData.put("name", tenant.getName());
            tenantData.put("email", tenant.getEmail());
            tenantData.put("subdomain", tenant.getSubdomain());
            tenantData.put("createdAt", tenant.getCreatedAt().toString());

            return ResponseEntity.ok(Map.of("success", true, "tenant", tenantData));

        } catch (Exception e) {
            logger.error("Error creating tenant: {}", e.getMessage(), e);
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    // ============================================================
    //         START: NEW ENDPOINT FOR EDIT MODAL (Unchanged)
    // ============================================================

    /**
     * GET TENANT BY ID (AJAX)
     * Fetches a single tenant's data to populate the edit modal.
     */
    @GetMapping("/tenants/{id}")
    @ResponseBody
    public ResponseEntity<?> getTenant(@PathVariable Long id) {
        // This re-uses your existing getTenantById method from TenantService
        Optional<Tenant> tenantOpt = tenantService.getTenantById(id);
        if (tenantOpt.isPresent()) {
            return ResponseEntity.ok(tenantOpt.get());
        } else {
            logger.warn("Tenant not found for ID: {}", id);
            return ResponseEntity.status(404).body(Map.of("error", "Tenant not found"));
        }
    }

    // ============================================================
    //         END: NEW ENDPOINT FOR EDIT MODAL
    // ============================================================


    // ============================================================
    //                    UPDATE TENANT (AJAX) (Unchanged)
    // ============================================================

    @PutMapping("/tenants/{id}")
    @ResponseBody
    public ResponseEntity<?> updateTenant(@PathVariable Long id, @RequestBody Map<String, String> payload) {
        try {
            String name = payload.get("name");
            String email = payload.get("email");
            String subdomain = payload.get("subdomain");

            logger.info("Updating tenant: {}", id);

            Tenant tenant = tenantService.updateTenant(id, name, email, subdomain);

            logger.info("✅ Tenant updated successfully: {}", tenant.getId());

            Map<String, Object> tenantData = new HashMap<>();
            tenantData.put("id", tenant.getId());
            tenantData.put("name", tenant.getName());
            tenantData.put("email", tenant.getEmail());
            tenantData.put("subdomain", tenant.getSubdomain());

            return ResponseEntity.ok(Map.of("success", true, "tenant", tenantData));

        } catch (Exception e) {
            logger.error("Error updating tenant: {}", e.getMessage(), e);
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    // ============================================================
    //                    DELETE TENANT (AJAX) (Unchanged)
    // ============================================================

    @DeleteMapping("/tenants/{id}")
    @ResponseBody
    public ResponseEntity<?> deleteTenant(@PathVariable Long id) {
        try {
            logger.info("Deleting tenant: {}", id);

            tenantService.deleteTenant(id);

            logger.info("✅ Tenant deleted successfully: {}", id);

            return ResponseEntity.ok(Map.of("success", true));

        } catch (Exception e) {
            logger.error("Error deleting tenant: {}", e.getMessage(), e);
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    // ============================================================
    //                    GET TENANT USERS (AJAX) (Unchanged)
    // ============================================================

    @GetMapping("/tenants/{id}/users")
    @ResponseBody
    public ResponseEntity<?> getTenantUsers(@PathVariable Long id) {
        try {
            List<User> users = userRepository.findByTenantId(id);

            // FIXED: Use wildcard map type to avoid compilation issues
            List<Map<String, Object>> userList = users.stream()
                    .map(user -> {
                        Map<String, Object> u = new HashMap<>();
                        u.put("id", user.getId());
                        u.put("fullName", user.getFullName());
                        u.put("email", user.getEmail());
                        u.put("role", user.getRole());
                        u.put("createdAt", user.getCreatedAt().toString());
                        return u;
                    })
                    .collect(Collectors.toList());

            return ResponseEntity.ok(Map.of("users", userList));

        } catch (Exception e) {
            logger.error("Error fetching tenant users: {}", e.getMessage(), e);
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
}