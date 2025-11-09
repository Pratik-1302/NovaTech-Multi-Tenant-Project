package com.novatech.service_app.controller;

import com.novatech.service_app.dto.SignupRequest;
import com.novatech.service_app.service.SsoManagementService;
import com.novatech.service_app.service.TenantContext;
import com.novatech.service_app.service.TenantService;
import com.novatech.service_app.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    private UserService userService;

    @Autowired
    private SsoManagementService ssoManagementService;

    @Autowired
    private TenantService tenantService;

    // ===================== LOGIN PAGE (FIXED) =====================
    @GetMapping("/login")
    public String loginPage(
            @RequestParam(value = "error", required = false) String error,
            @RequestParam(value = "success", required = false) String success,
            Model model) {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getPrincipal())) {
            logger.info("User already authenticated, redirecting to /home");
            return "redirect:/home";
        }

        logger.info("=== LOGIN PAGE ACCESSED ===");
        logger.info("Tenant Context: {}", TenantContext.getTenantId());
        logger.info("Error param: {}, Success param: {}", error, success);

        if (error != null) {
            model.addAttribute("error", "Invalid email or password");
        }

        if (success != null) {
            // Updated to be more specific for new tenants
            if (success.equals("tenant")) {
                model.addAttribute("success", "Your new organization is ready! Please login.");
            } else {
                model.addAttribute("success", "Registration successful! Please login.");
            }
        }

        // ===================================================================
        // ✅ START: TENANT-ISOLATED SSO LOGIC
        // ===================================================================
        Long tenantId = TenantContext.getTenantId();

        // Only check for SSO options if we are in a tenant context
        if (tenantId != null) {
            try {
                // These methods now correctly use the tenantId from TenantContext
                boolean jwtEnabled = ssoManagementService.isJwtEnabled();
                boolean oidcEnabled = ssoManagementService.isOidcEnabled();
                boolean samlEnabled = ssoManagementService.isSamlEnabled();

                model.addAttribute("jwtEnabled", jwtEnabled);
                model.addAttribute("oidcEnabled", oidcEnabled);
                model.addAttribute("samlEnabled", samlEnabled);
                model.addAttribute("ssoEnabled", jwtEnabled || oidcEnabled || samlEnabled);

                logger.info("Tenant [{}] SSO Status - JWT: {}, OIDC: {}, SAML: {}",
                        tenantId, jwtEnabled, oidcEnabled, samlEnabled);
            } catch (Exception e) {
                logger.error("Error checking SSO status for tenant {}: {}", tenantId, e.getMessage(), e);
                model.addAttribute("ssoEnabled", false);
            }
        } else {
            // Superadmin login page (localhost) - NO SSO options
            model.addAttribute("jwtEnabled", false);
            model.addAttribute("oidcEnabled", false);
            model.addAttribute("samlEnabled", false);
            model.addAttribute("ssoEnabled", false);
            logger.info("Superadmin login page - SSO disabled");
        }
        // ===================================================================
        // ✅ END: TENANT-ISOLATED SSO LOGIC
        // ===================================================================

        return "login";
    }

    // ===================== SIGNUP PAGE (Unchanged) =====================
    @GetMapping("/signup")
    public String signupPage(Model model) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getPrincipal())) {
            logger.info("Authenticated user tried to access signup — redirecting to /home");
            return "redirect:/home";
        }

        Long tenantId = TenantContext.getTenantId();
        logger.info("=== SIGNUP PAGE ACCESSED === (Tenant: {})", tenantId);

        if (tenantId == null) {
            // --- PUBLIC SIGNUP ---
            logger.info("No tenant context. Showing public tenant registration page.");
            if (!model.containsAttribute("publicSignupRequest")) {
                model.addAttribute("publicSignupRequest", new java.util.HashMap<>());
            }
            return "public-signup";
        } else {
            // --- TENANT SIGNUP ---
            logger.info("Tenant context found. Showing user registration page for tenant: {}", tenantId);
            model.addAttribute("signupRequest", new SignupRequest());
            model.addAttribute("tenantContext", true);
            return "signup";
        }
    }

    // ===================== SIGNUP FORM HANDLER (Unchanged) =====================
    @PostMapping("/signup")
    public String registerUser(
            @Valid @ModelAttribute("signupRequest") SignupRequest signupRequest,
            BindingResult result,
            Model model) {

        Long tenantId = TenantContext.getTenantId();
        logger.info("=== (TENANT) SIGNUP FORM SUBMITTED ===");
        logger.info("Full Name: {}, Email: {}, Tenant: {}",
                signupRequest.getFullName(), signupRequest.getEmail(), tenantId);

        if (result.hasErrors()) {
            logger.error("Validation errors: {}", result.getAllErrors());
            return "signup";
        }

        if (!signupRequest.getPassword().equals(signupRequest.getConfirmPassword())) {
            logger.warn("Passwords do not match for email: {}", signupRequest.getEmail());
            model.addAttribute("error", "Passwords do not match");
            return "signup";
        }

        if (userService.emailExists(signupRequest.getEmail())) {
            logger.warn("Email already registered: {}", signupRequest.getEmail());
            model.addAttribute("error", "Email already registered");
            return "signup";
        }

        try {
            userService.registerUser(
                    signupRequest.getFullName(),
                    signupRequest.getEmail(),
                    signupRequest.getPassword()
            );

            if (tenantId != null) {
                logger.info("✅ User registered under tenant: {}", tenantId);
            } else {
                logger.info("✅ User registered (no tenant - superadmin context)");
            }

            return "redirect:/login?success=true";

        } catch (Exception e) {
            logger.error("Error during registration: {}", e.getMessage(), e);
            model.addAttribute("error", "Registration failed: " + e.getMessage());
            return "signup";
        }
    }

    // ===================== PUBLIC SIGNUP HANDLER (Unchanged) =====================
    @PostMapping("/public-signup")
    public String handlePublicSignup(
            @RequestParam String organizationName,
            @RequestParam String subdomain,
            @RequestParam String fullName,
            @RequestParam String email,
            @RequestParam String password,
            @RequestParam String confirmPassword,
            RedirectAttributes redirectAttributes,
            HttpServletRequest request) {

        logger.info("=== PUBLIC SIGNUP SUBMITTED ===");
        logger.info("Org: {}, Subdomain: {}, Email: {}", organizationName, subdomain, email);

        if (!password.equals(confirmPassword)) {
            logger.warn("Passwords do not match for email: {}", email);
            redirectAttributes.addFlashAttribute("error", "Passwords do not match");
            return "redirect:/signup";
        }

        if (!subdomain.matches("^[a-z0-9-]+$") || subdomain.length() < 3) {
            logger.warn("Invalid subdomain format: {}", subdomain);
            redirectAttributes.addFlashAttribute("error", "Subdomain must be at least 3 characters and contain only lowercase letters, numbers, and hyphens.");
            return "redirect:/signup";
        }

        try {
            tenantService.registerNewTenantAndAdmin(
                    organizationName,
                    email,
                    password,
                    subdomain,
                    fullName
            );

            logger.info("✅ New tenant and admin created for subdomain: {}", subdomain);

            String scheme = request.getScheme();
            String port = (request.getServerPort() == 80 || request.getServerPort() == 443) ? "" : ":" + request.getServerPort();
            String newLoginUrl = scheme + "://" + subdomain + ".localhost" + port + "/login?success=tenant";

            return "redirect:" + newLoginUrl;

        } catch (Exception e) {
            logger.error("Error during public registration: {}", e.getMessage(), e);
            redirectAttributes.addFlashAttribute("error", e.getMessage());
            return "redirect:/signup";
        }
    }
}