package com.novatech.service_app.controller;

import com.novatech.service_app.entity.SsoConfiguration;
import com.novatech.service_app.entity.Tenant;
import com.novatech.service_app.entity.User;
import com.novatech.service_app.repository.TenantRepository;
import com.novatech.service_app.service.SsoManagementService;
import com.novatech.service_app.service.UserService;
import com.novatech.service_app.service.TenantContext;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.security.Principal;
import java.util.List;
import java.util.Optional;

/**
 * Admin Controller - Handles admin dashboard, SSO configuration, and user management
 */
@Controller
@RequestMapping("/admin")
public class AdminController {

    private static final Logger logger = LoggerFactory.getLogger(AdminController.class);

    @Autowired
    private UserService userService;

    @Autowired
    private SsoManagementService ssoManagementService;

    @Autowired
    private TenantRepository tenantRepository;

    // ===================== ADMIN DASHBOARD (Unchanged) =====================

    @GetMapping("/dashboard")
    public String adminDashboard(Model model, Principal principal) {
        logger.info("=== ADMIN DASHBOARD ACCESSED ===");
        if (principal != null) {
            User admin = userService.findByEmail(principal.getName());
            model.addAttribute("adminName", admin != null ? admin.getFullName() : "Admin");
        }
        List<User> users = userService.getAllUsers();
        model.addAttribute("users", users);
        model.addAttribute("jwtEnabled", ssoManagementService.isJwtEnabled());
        model.addAttribute("oidcEnabled", ssoManagementService.isOidcEnabled());
        model.addAttribute("samlEnabled", ssoManagementService.isSamlEnabled());
        logger.info("Total users: {}", users.size());
        return "admin-dashboard";
    }

    // ===================== DYNAMIC URL HELPERS (Unchanged) =====================

    private String getTenantBaseUrl(HttpServletRequest request) {
        Long tenantId = TenantContext.getTenantId();
        if (tenantId == null) {
            String defaultDomain = System.getenv("APP_DOMAIN");
            if (defaultDomain == null || defaultDomain.isEmpty()) {
                defaultDomain = "localhost:8080";
            }
            return "http://" + defaultDomain;
        }

        String subdomain = tenantRepository.findById(tenantId)
                .map(Tenant::getSubdomain)
                .orElse("localhost");

        // Get production domain from environment
        String appDomain = System.getenv("APP_DOMAIN");
        if (appDomain == null || appDomain.isEmpty()) {
            // Development mode
            int port = request.getServerPort();
            String portString = (port == 80 || port == 443) ? "" : ":" + port;
            return "http://" + subdomain + ".localhost" + portString;
        } else {
            // Production mode
            String scheme = System.getenv("APP_SCHEME");
            if (scheme == null || scheme.isEmpty()) {
                scheme = "https";
            }
            return scheme + "://" + subdomain + "." + appDomain;
        }
    }

    // This helper is still used by JWT and OIDC
    private String cleanEndpointUrl(String url) {
        if (url == null) {
            return null;
        }
        int queryIndex = url.indexOf('?');
        if (queryIndex != -1) {
            return url.substring(0, queryIndex);
        }
        return url;
    }


    // ===================== JWT CONFIG (Unchanged) =====================

    @GetMapping("/jwt-config")
    public String jwtConfigPage(Model model, HttpServletRequest request) {
        logger.info("=== JWT CONFIG PAGE ACCESSED ===");
        SsoConfiguration jwtConfig = ssoManagementService.getConfigByType("JWT").orElse(new SsoConfiguration());
        jwtConfig.setSsoType("JWT");

        model.addAttribute("tenantCallbackUrl", getTenantBaseUrl(request) + "/sso/callback");
        model.addAttribute("ssoConfig", jwtConfig);
        return "jwt-config";
    }

    @PostMapping("/jwt-config/save")
    public String saveJwtConfig(
            @RequestParam String providerName,
            @RequestParam String clientId,
            @RequestParam String clientSecret,
            @RequestParam String authorizationEndpoint,
            @RequestParam(required = false, defaultValue = "false") boolean enabled,
            RedirectAttributes redirectAttributes,
            HttpServletRequest request
    ) {
        try {
            logger.info("=== SAVING JWT CONFIG ===");
            Long tenantId = TenantContext.getTenantId();
            if (tenantId == null) {
                redirectAttributes.addFlashAttribute("error", "❌ No tenant context. Access via tenant subdomain.");
                return "redirect:/admin/jwt-config";
            }

            SsoConfiguration jwtConfig = new SsoConfiguration();
            jwtConfig.setSsoType("JWT");
            jwtConfig.setProviderName(providerName);
            jwtConfig.setClientId(clientId);
            jwtConfig.setClientSecret(clientSecret);
            jwtConfig.setAuthorizationEndpoint(cleanEndpointUrl(authorizationEndpoint)); // ✅ Cleaned
            jwtConfig.setRedirectUri(getTenantBaseUrl(request) + "/sso/callback");
            jwtConfig.setCertificatePath("classpath:miniorange_jwt.cer");
            jwtConfig.setEnabled(enabled);

            if (!ssoManagementService.isConfigValid(jwtConfig)) {
                redirectAttributes.addFlashAttribute("error", "❌ Invalid JWT configuration. Please fill all required fields.");
                return "redirect:/admin/jwt-config";
            }

            ssoManagementService.saveOrUpdateConfig(jwtConfig);
            redirectAttributes.addFlashAttribute("success", "✅ JWT configuration saved successfully!");
            return "redirect:/admin/dashboard";

        } catch (Exception e) {
            logger.error("❌ Error saving JWT config: {}", e.getMessage(), e);
            redirectAttributes.addFlashAttribute("error", "❌ Error: " + e.getMessage());
            return "redirect:/admin/jwt-config";
        }
    }

    @PostMapping("/jwt-config/toggle")
    @ResponseBody
    public String toggleJwt(@RequestParam boolean enabled) {
        try {
            boolean success = ssoManagementService.toggleSsoEnabled("JWT", enabled);
            if (success) {
                logger.info("✅ JWT SSO toggled: {}", enabled);
                return "{\"success\": true, \"enabled\": " + enabled + "}";
            } else {
                return "{\"success\": false, \"message\": \"JWT config not found\"}";
            }
        } catch (Exception e) {
            logger.error("❌ Error toggling JWT: {}", e.getMessage());
            return "{\"success\": false, \"message\": \"" + e.getMessage() + "\"}";
        }
    }


    // ===================== OIDC CONFIG (Unchanged) =====================

    @GetMapping("/oidc-config")
    public String oidcConfigPage(Model model, HttpServletRequest request) {
        logger.info("=== OIDC CONFIG PAGE ACCESSED ===");
        SsoConfiguration oidcConfig = ssoManagementService.getConfigByType("OIDC").orElse(new SsoConfiguration());
        oidcConfig.setSsoType("OIDC");

        model.addAttribute("tenantCallbackUrl", getTenantBaseUrl(request) + "/sso/callback");
        model.addAttribute("ssoConfig", oidcConfig);
        return "oidc-config";
    }

    @PostMapping("/oidc-config/save")
    public String saveOidcConfig(
            @RequestParam String providerName,
            @RequestParam String clientId,
            @RequestParam String clientSecret,
            @RequestParam String authorizationEndpoint,
            @RequestParam String tokenEndpoint,
            @RequestParam(required = false) String userinfoEndpoint,
            @RequestParam(required = false, defaultValue = "openid profile email") String scopes,
            @RequestParam(required = false, defaultValue = "false") boolean enabled,
            RedirectAttributes redirectAttributes,
            HttpServletRequest request
    ) {
        try {
            logger.info("=== SAVING OIDC CONFIG ===");
            Long tenantId = TenantContext.getTenantId();
            if (tenantId == null) {
                redirectAttributes.addFlashAttribute("error", "❌ No tenant context. Access via tenant subdomain.");
                return "redirect:/admin/oidc-config";
            }

            SsoConfiguration oidcConfig = new SsoConfiguration();
            oidcConfig.setSsoType("OIDC");
            oidcConfig.setProviderName(providerName);
            oidcConfig.setClientId(clientId);
            oidcConfig.setClientSecret(clientSecret);
            oidcConfig.setAuthorizationEndpoint(cleanEndpointUrl(authorizationEndpoint)); // ✅ Cleaned
            oidcConfig.setTokenEndpoint(cleanEndpointUrl(tokenEndpoint)); // ✅ Cleaned
            oidcConfig.setUserinfoEndpoint(cleanEndpointUrl(userinfoEndpoint)); // ✅ Cleaned
            oidcConfig.setRedirectUri(getTenantBaseUrl(request) + "/sso/callback");
            oidcConfig.setScopes(scopes != null && !scopes.isBlank() ? scopes : "openid profile email");
            oidcConfig.setEnabled(enabled);

            if (!ssoManagementService.isConfigValid(oidcConfig)) {
                redirectAttributes.addFlashAttribute("error", "❌ Invalid OIDC configuration. Please fill all required fields.");
                return "redirect:/admin/oidc-config";
            }

            ssoManagementService.saveOrUpdateConfig(oidcConfig);
            redirectAttributes.addFlashAttribute("success", "✅ OIDC configuration saved successfully!");
            return "redirect:/admin/dashboard";

        } catch (Exception e) {
            logger.error("❌ Error saving OIDC config: {}", e.getMessage(), e);
            redirectAttributes.addFlashAttribute("error", "❌ Error: " + e.getMessage());
            return "redirect:/admin/oidc-config";
        }
    }

    @PostMapping("/oidc-config/toggle")
    @ResponseBody
    public String toggleOidc(@RequestParam boolean enabled) {
        try {
            boolean success = ssoManagementService.toggleSsoEnabled("OIDC", enabled);
            if (success) {
                logger.info("✅ OIDC SSO toggled: {}", enabled);
                return "{\"success\": true, \"enabled\": " + enabled + "}";
            } else {
                return "{\"success\": false, \"message\": \"OIDC config not found\"}";
            }
        } catch (Exception e) {
            logger.error("❌ Error toggling OIDC: {}", e.getMessage());
            return "{\"success\": false, \"message\": \"" + e.getMessage() + "\"}";
        }
    }

    // ===================== SAML CONFIG (MODIFIED) =====================

    @GetMapping("/saml-config")
    public String samlConfigPage(Model model, HttpServletRequest request) {
        logger.info("=== SAML CONFIG PAGE ACCESSED ===");
        SsoConfiguration samlConfig = ssoManagementService.getConfigByType("SAML").orElse(new SsoConfiguration());
        samlConfig.setSsoType("SAML");

        String baseUrl = getTenantBaseUrl(request);
        model.addAttribute("tenantCallbackUrl", baseUrl + "/sso/callback");
        model.addAttribute("tenantEntityId", baseUrl);

        model.addAttribute("ssoConfig", samlConfig);
        return "saml-config";
    }

    @PostMapping("/saml-config/save")
    public String saveSamlConfig(
            @RequestParam String providerName,
            @RequestParam String authorizationEndpoint,
            @RequestParam String issuer,
            @RequestParam(required = false, defaultValue = "false") boolean enabled,
            RedirectAttributes redirectAttributes,
            HttpServletRequest request
    ) {
        try {
            logger.info("=== SAVING SAML CONFIG ===");
            Long tenantId = TenantContext.getTenantId();
            if (tenantId == null) {
                redirectAttributes.addFlashAttribute("error", "❌ No tenant context. Access via tenant subdomain.");
                return "redirect:/admin/saml-config";
            }

            String baseUrl = getTenantBaseUrl(request);

            SsoConfiguration samlConfig = new SsoConfiguration();
            samlConfig.setSsoType("SAML");
            samlConfig.setProviderName(providerName);

            // ✅ ========================================================
            // ✅ THIS IS THE FIX. We no longer clean the SAML endpoint.
            // ✅ ========================================================
            samlConfig.setAuthorizationEndpoint(authorizationEndpoint);

            samlConfig.setIssuer(issuer);
            samlConfig.setCertificatePath("classpath:saml_certificate.cer");
            samlConfig.setRedirectUri(baseUrl + "/sso/callback");
            samlConfig.setDomain(baseUrl);
            samlConfig.setEnabled(enabled);

            if (!ssoManagementService.isConfigValid(samlConfig)) {
                redirectAttributes.addFlashAttribute("error", "❌ Invalid SAML configuration. Please fill all required fields.");
                return "redirect:/admin/saml-config";
            }

            ssoManagementService.saveOrUpdateConfig(samlConfig);
            redirectAttributes.addFlashAttribute("success", "✅ SAML configuration saved successfully!");
            return "redirect:/admin/dashboard";

        } catch (Exception e) {
            logger.error("❌ Error saving SAML config: {}", e.getMessage(), e);
            redirectAttributes.addFlashAttribute("error", "❌ Error: " + e.getMessage());
            return "redirect:/admin/saml-config";
        }
    }

    @PostMapping("/saml-config/toggle")
    @ResponseBody
    public String toggleSaml(@RequestParam boolean enabled) {
        try {
            boolean success = ssoManagementService.toggleSsoEnabled("SAML", enabled);
            if (success) {
                logger.info("✅ SAML SSO toggled: {}", enabled);
                return "{\"success\": true, \"enabled\": " + enabled + "}";
            } else {
                return "{\"success\": false, \"message\": \"SAML config not found\"}";
            }
        } catch (Exception e) {
            logger.error("❌ Error toggling SAML: {}", e.getMessage());
            return "{\"success\": false, \"message\": \"" + e.getMessage() + "\"}";
        }
    }

    // ===================== USER MANAGEMENT (Unchanged) =====================

    @PostMapping("/users")
    public String createUser(
            @RequestParam String fullName,
            @RequestParam String email,
            @RequestParam String password,
            @RequestParam(defaultValue = "ROLE_USER") String role,
            RedirectAttributes redirectAttributes) {

        try {
            logger.info("=== CREATING NEW USER ===");
            if (userService.emailExists(email)) {
                redirectAttributes.addFlashAttribute("error", "❌ Email already exists");
                return "redirect:/admin/dashboard";
            }
            if (role.equals("ROLE_SUPER_ADMIN")) {
                throw new AccessDeniedException("Access Denied: A new Super Admin cannot be created.");
            }
            User newUser = new User();
            newUser.setFullName(fullName);
            newUser.setEmail(email);
            newUser.setPassword(password);
            newUser.setRole(role);
            userService.createUserWithPassword(newUser, password);
            redirectAttributes.addFlashAttribute("success", "✅ User created successfully");
        } catch (AccessDeniedException e) {
            logger.warn("❌ ACCESS DENIED: Tried to create a Super Admin.");
            redirectAttributes.addFlashAttribute("error", "❌ " + e.getMessage());
        } catch (Exception e) {
            logger.error("❌ Error creating user: {}", e.getMessage(), e);
            redirectAttributes.addFlashAttribute("error", "❌ Error: " + e.getMessage());
        }
        return "redirect:/admin/dashboard";
    }

    @PostMapping("/users/update/{id}")
    public String updateUser(
            @PathVariable Long id,
            @RequestParam String fullName,
            @RequestParam(required = false) String password,
            @RequestParam String role,
            RedirectAttributes redirectAttributes) {

        try {
            logger.info("=== UPDATING USER ===");
            userService.updateUserDetails(id, fullName, password, role);
            redirectAttributes.addFlashAttribute("success", "✅ User updated successfully");
        } catch (AccessDeniedException e) {
            logger.warn("❌ ACCESS DENIED: Tried to modify Super Admin.");
            redirectAttributes.addFlashAttribute("error", "❌ " + e.getMessage());
        } catch (Exception e) {
            logger.error("❌ Error updating user: {}", e.getMessage(), e);
            redirectAttributes.addFlashAttribute("error", "❌ Error: " + e.getMessage());
        }
        return "redirect:/admin/dashboard";
    }

    @PostMapping("/users/delete/{id}")
    public String deleteUser(
            @PathVariable Long id,
            RedirectAttributes redirectAttributes) {

        try {
            logger.info("=== DELETING USER ===");
            userService.deleteUserById(id);
            redirectAttributes.addFlashAttribute("success", "✅ User deleted successfully");
        } catch (AccessDeniedException e) {
            logger.warn("❌ ACCESS DENIED: Tried to delete Super Admin.");
            redirectAttributes.addFlashAttribute("error", "❌ " + e.getMessage());
        } catch (Exception e) {
            logger.error("❌ Error deleting user: {}", e.getMessage(), e);
            redirectAttributes.addFlashAttribute("error", "❌ Error: " + e.getMessage());
        }
        return "redirect:/admin/dashboard";
    }
}