package com.novatech.service_app.controller;

import com.novatech.service_app.entity.SsoConfiguration;
import com.novatech.service_app.entity.User;
import com.novatech.service_app.service.SsoManagementService;
import com.novatech.service_app.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.AccessDeniedException; // ✅ Keep this
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.security.Principal; // ✅ Keep this for the dashboard welcome
import java.util.List;

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

    @Value("${app.base-url:http://localhost:8080}")
    private String appBaseUrl;

    @Value("${app.callback-url:http://localhost:8080/sso/callback}")
    private String appCallbackUrl;

    // ===================== ADMIN DASHBOARD =====================

    @GetMapping("/dashboard")
    public String adminDashboard(Model model, Principal principal) {
        logger.info("=== ADMIN DASHBOARD ACCESSED ===");
        if (principal != null) {
            User admin = userService.findByEmail(principal.getName());
            model.addAttribute("adminName", admin != null ? admin.getFullName() : "Admin");
            // ❌ REMOVED: model.addAttribute("currentUserRole", ...);
        }
        List<User> users = userService.getAllUsers();
        model.addAttribute("users", users);
        model.addAttribute("jwtEnabled", ssoManagementService.isJwtEnabled());
        model.addAttribute("oidcEnabled", ssoManagementService.isOidcEnabled());
        model.addAttribute("samlEnabled", ssoManagementService.isSamlEnabled());
        logger.info("Total users: {}", users.size());
        return "admin-dashboard";
    }

    // ===================== (All SSO Configuration methods are unchanged) =====================

    @GetMapping("/jwt-config")
    public String jwtConfigPage(Model model) {
        logger.info("=== JWT CONFIG PAGE ACCESSED ===");
        SsoConfiguration jwtConfig = ssoManagementService.getConfigByType("JWT").orElse(new SsoConfiguration());
        jwtConfig.setSsoType("JWT");
        model.addAttribute("ssoConfig", jwtConfig);
        return "jwt-config";
    }

    @PostMapping("/jwt-config/save")
    public String saveJwtConfig(
            @RequestParam String providerName,
            @RequestParam String clientId,
            @RequestParam String clientSecret,
            @RequestParam String authorizationEndpoint,
            @RequestParam String redirectUri,
            @RequestParam String domain,
            @RequestParam String certificatePath,
            @RequestParam(required = false, defaultValue = "false") boolean enabled,
            RedirectAttributes redirectAttributes) {

        try {
            logger.info("=== SAVING JWT CONFIG ===");
            SsoConfiguration jwtConfig = new SsoConfiguration();
            jwtConfig.setSsoType("JWT");
            jwtConfig.setProviderName(providerName);
            jwtConfig.setClientId(clientId);
            jwtConfig.setClientSecret(clientSecret);
            jwtConfig.setAuthorizationEndpoint(authorizationEndpoint);
            jwtConfig.setRedirectUri(redirectUri);
            jwtConfig.setDomain(domain);
            jwtConfig.setCertificatePath(certificatePath);
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

    @GetMapping("/oidc-config")
    public String oidcConfigPage(Model model) {
        logger.info("=== OIDC CONFIG PAGE ACCESSED ===");
        SsoConfiguration oidcConfig = ssoManagementService.getConfigByType("OIDC").orElse(new SsoConfiguration());
        oidcConfig.setSsoType("OIDC");
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
            @RequestParam String redirectUri,
            @RequestParam(required = false) String domain,
            @RequestParam(required = false, defaultValue = "openid profile email") String scopes,
            @RequestParam(required = false, defaultValue = "false") boolean enabled,
            RedirectAttributes redirectAttributes) {

        try {
            logger.info("=== SAVING OIDC CONFIG ===");
            SsoConfiguration oidcConfig = new SsoConfiguration();
            oidcConfig.setSsoType("OIDC");
            oidcConfig.setProviderName(providerName);
            oidcConfig.setClientId(clientId);
            oidcConfig.setClientSecret(clientSecret);
            oidcConfig.setAuthorizationEndpoint(authorizationEndpoint);
            oidcConfig.setTokenEndpoint(tokenEndpoint);
            oidcConfig.setUserinfoEndpoint(userinfoEndpoint);
            oidcConfig.setRedirectUri(redirectUri);
            oidcConfig.setDomain(domain);
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

    @GetMapping("/saml-config")
    public String samlConfigPage(Model model) {
        logger.info("=== SAML CONFIG PAGE ACCESSED ===");
        SsoConfiguration samlConfig = ssoManagementService.getConfigByType("SAML").orElse(new SsoConfiguration());
        samlConfig.setSsoType("SAML");
        if (samlConfig.getRedirectUri() == null) {
            samlConfig.setRedirectUri(appCallbackUrl);
        }
        if (samlConfig.getDomain() == null) {
            samlConfig.setDomain(appBaseUrl);
        }
        model.addAttribute("ssoConfig", samlConfig);
        return "saml-config";
    }

    @PostMapping("/saml-config/save")
    public String saveSamlConfig(
            @RequestParam String providerName,
            @RequestParam String authorizationEndpoint,
            @RequestParam String issuer,
            @RequestParam String certificatePath,
            @RequestParam(required = false, defaultValue = "false") boolean enabled,
            RedirectAttributes redirectAttributes) {

        try {
            logger.info("=== SAVING SAML CONFIG ===");
            SsoConfiguration samlConfig = new SsoConfiguration();
            samlConfig.setSsoType("SAML");
            samlConfig.setProviderName(providerName);
            samlConfig.setAuthorizationEndpoint(authorizationEndpoint);
            samlConfig.setIssuer(issuer);
            samlConfig.setCertificatePath(certificatePath);
            samlConfig.setEnabled(enabled);
            samlConfig.setRedirectUri(appCallbackUrl);
            samlConfig.setDomain(appBaseUrl);

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


    // ===================== USER MANAGEMENT =====================

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
            // ✅ Security Check: Prevent creating a Super Admin
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
        } catch (AccessDeniedException e) { // ✅ Catch the specific error
            logger.warn("❌ ACCESS DENIED: Tried to create a Super Admin.");
            redirectAttributes.addFlashAttribute("error", "❌ " + e.getMessage());
        } catch (Exception e) {
            logger.error("❌ Error creating user: {}", e.getMessage(), e);
            redirectAttributes.addFlashAttribute("error", "❌ Error: " + e.getMessage());
        }
        return "redirect:/admin/dashboard";
    }

    /**
     * ✅ UPDATED: Removed Principal
     */
    @PostMapping("/users/update/{id}")
    public String updateUser(
            @PathVariable Long id,
            @RequestParam String fullName,
            @RequestParam(required = false) String password,
            @RequestParam String role,
            RedirectAttributes redirectAttributes) { // ❌ REMOVED Principal

        try {
            logger.info("=== UPDATING USER ===");
            // ✅ CALL the simplified service method
            userService.updateUserDetails(id, fullName, password, role);
            redirectAttributes.addFlashAttribute("success", "✅ User updated successfully");
        } catch (AccessDeniedException e) { // ✅ Catch the specific error
            logger.warn("❌ ACCESS DENIED: Tried to modify Super Admin.");
            redirectAttributes.addFlashAttribute("error", "❌ " + e.getMessage());
        } catch (Exception e) {
            logger.error("❌ Error updating user: {}", e.getMessage(), e);
            redirectAttributes.addFlashAttribute("error", "❌ Error: " + e.getMessage());
        }
        return "redirect:/admin/dashboard";
    }

    /**
     * ✅ UPDATED: Removed Principal
     */
    @PostMapping("/users/delete/{id}")
    public String deleteUser(
            @PathVariable Long id,
            RedirectAttributes redirectAttributes) { // ❌ REMOVED Principal

        try {
            logger.info("=== DELETING USER ===");
            // ✅ CALL the simplified service method
            userService.deleteUserById(id);
            redirectAttributes.addFlashAttribute("success", "✅ User deleted successfully");
        } catch (AccessDeniedException e) { // ✅ Catch the specific error
            logger.warn("❌ ACCESS DENIED: Tried to delete Super Admin.");
            redirectAttributes.addFlashAttribute("error", "❌ " + e.getMessage());
        } catch (Exception e) {
            logger.error("❌ Error deleting user: {}", e.getMessage(), e);
            redirectAttributes.addFlashAttribute("error", "❌ Error: " + e.getMessage());
        }
        return "redirect:/admin/dashboard";
    }
}
