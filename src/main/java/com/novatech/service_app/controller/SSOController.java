package com.novatech.service_app.controller;

import com.novatech.service_app.entity.Tenant;
import com.novatech.service_app.entity.User;
import com.novatech.service_app.repository.TenantRepository;
import com.novatech.service_app.repository.UserRepository;
import com.novatech.service_app.service.SSOService;
import com.novatech.service_app.service.OidcService;
import com.novatech.service_app.service.SamlService;
import com.novatech.service_app.service.SsoManagementService;
import com.novatech.service_app.service.TenantContext;
import com.novatech.service_app.service.CustomUserDetails;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.IOException;
import java.util.Map;
import java.util.Optional;

@Controller
@RequestMapping("/sso")
public class SSOController {

    private static final Logger logger = LoggerFactory.getLogger(SSOController.class);

    @Autowired
    private SSOService ssoService;

    @Autowired
    private OidcService oidcService;

    @Autowired
    private SamlService samlService;

    @Autowired
    private SsoManagementService ssoManagementService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TenantRepository tenantRepository;

    @Value("${app.logout-success-url:http://localhost:8080/login}")
    private String loginPageUrl;

    // ===================================================================
    // ✅ Build redirect URL with proper authentication setup
    // ===================================================================
    private String buildPostSsoRedirectUrl(HttpServletRequest request, Long tenantId, String userType) {
        logger.info("🔧 [buildPostSsoRedirectUrl] Building redirect URL - tenantId: {}, userType: {}", tenantId, userType);

        if (tenantId == null) {
            logger.error("❌ [buildPostSsoRedirectUrl] CRITICAL: tenantId is NULL");
            return loginPageUrl + "?error=no_tenant";
        }

        Optional<Tenant> tenantOpt = tenantRepository.findById(tenantId);
        if (tenantOpt.isEmpty()) {
            logger.error("❌ [buildPostSsoRedirectUrl] Tenant not found for ID: {}", tenantId);
            return loginPageUrl + "?error=tenant_not_found";
        }

        String subdomain = tenantOpt.get().getSubdomain();
        String scheme = request.getScheme();
        int port = request.getServerPort();
        String portString = (port == 80 || port == 443) ? "" : ":" + port;

        // ✅ KEY: Redirect based on user type
        String redirectPath = switch (userType) {
            case "SUPERADMIN" -> {
                logger.info("🎯 [buildPostSsoRedirectUrl] User is SUPERADMIN - redirecting to /superadmin/dashboard");
                yield "/superadmin/dashboard";
            }
            case "TENANT_ADMIN" -> {
                logger.info("🎯 [buildPostSsoRedirectUrl] User is TENANT_ADMIN - redirecting to /admin/dashboard");
                yield "/admin/dashboard";
            }
            case "END_USER" -> {
                logger.info("🎯 [buildPostSsoRedirectUrl] User is END_USER - redirecting to /home");
                yield "/home";
            }
            default -> {
                logger.warn("⚠️ [buildPostSsoRedirectUrl] Unknown userType: {} - defaulting to /home", userType);
                yield "/home";
            }
        };

        String redirectUrl = scheme + "://" + subdomain + ".localhost" + portString + redirectPath;
        logger.info("✅ [buildPostSsoRedirectUrl] Final URL: {}", redirectUrl);

        return redirectUrl;
    }

    // ===================================================================
    // ✅ Complete authentication setup with detailed logging
    // ===================================================================
    private void setupCompleteAuthentication(User user, HttpServletRequest request, Long tenantId) {
        logger.info("═══════════════════════════════════════════════════════");
        logger.info("🔐 [setupCompleteAuthentication] STARTING");
        logger.info("═══════════════════════════════════════════════════════");

        logger.info("📋 User Details:");
        logger.info("   - Email: {}", user.getEmail());
        logger.info("   - ID: {}", user.getId());
        logger.info("   - Role: {}", user.getRole());
        logger.info("   - Full Name: {}", user.getFullName());
        logger.info("   - Tenant ID: {}", tenantId);

        // ✅ Step 1: Determine user type
        String userType = "END_USER";
        if ("ROLE_ADMIN".equals(user.getRole())) {
            userType = "TENANT_ADMIN";
        }
        if ("ROLE_SUPERADMIN".equals(user.getRole())) {
            userType = "SUPERADMIN";
        }
        logger.info("📌 User Type determined: {}", userType);

        // ✅ Step 2: Create custom user details
        UserDetails userDetails = new CustomUserDetails(
                user.getEmail(),
                user.getPasswordHash(),
                user.getRole(),
                user.getId(),
                tenantId,
                userType,
                user.getFullName()
        );
        logger.info("✅ CustomUserDetails created");

        // ✅ Step 3: Create authentication token
        UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        logger.info("✅ Authentication token created with {} authorities", userDetails.getAuthorities().size());

        // ✅ Step 4: Set in security context
        SecurityContextHolder.getContext().setAuthentication(authToken);
        logger.info("✅ Authentication set in SecurityContextHolder");
        logger.info("   - Principal: {}", SecurityContextHolder.getContext().getAuthentication().getPrincipal());
        logger.info("   - Authenticated: {}", SecurityContextHolder.getContext().getAuthentication().isAuthenticated());

        // ✅ Step 5: Create and populate session
        HttpSession session = request.getSession(true);
        logger.info("✅ Session created: {}", session.getId());

        session.setAttribute("userType", userType);
        session.setAttribute("userId", user.getId());
        session.setAttribute("tenantId", tenantId);
        session.setAttribute("displayName", user.getFullName());
        session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());

        logger.info("✅ Session attributes set:");
        logger.info("   - userType: {}", session.getAttribute("userType"));
        logger.info("   - userId: {}", session.getAttribute("userId"));
        logger.info("   - tenantId: {}", session.getAttribute("tenantId"));
        logger.info("   - displayName: {}", session.getAttribute("displayName"));
        logger.info("   - SPRING_SECURITY_CONTEXT: {}", (session.getAttribute("SPRING_SECURITY_CONTEXT") != null ? "SET" : "NULL"));

        logger.info("═══════════════════════════════════════════════════════");
        logger.info("✅ [setupCompleteAuthentication] COMPLETE");
        logger.info("═══════════════════════════════════════════════════════");
    }

    // ===================================================================
    // SSO LOGIN ENDPOINT
    // ===================================================================
    @GetMapping("/login")
    public String ssoLogin(@RequestParam(value = "type", defaultValue = "jwt") String ssoType) {
        logger.info("🔄 [ssoLogin] Endpoint called - type: {}", ssoType);
        try {
            if (TenantContext.getTenantId() == null) {
                logger.error("❌ [ssoLogin] No tenant context!");
                return "redirect:" + loginPageUrl + "?error=sso_no_tenant";
            }

            logger.info("=== SSO LOGIN INITIATED ===");
            logger.info("SSO Type: {}", ssoType.toUpperCase());
            ssoType = ssoType.toUpperCase();

            if (!ssoManagementService.isSsoTypeEnabled(ssoType)) {
                logger.error("❌ [ssoLogin] SSO type {} is not enabled", ssoType);
                return "redirect:" + loginPageUrl + "?error=sso_disabled";
            }

            String authorizationUrl = ssoService.getAuthorizationUrl(ssoType);
            logger.info("➡️ [ssoLogin] Redirecting to: {}", authorizationUrl);
            return "redirect:" + authorizationUrl;
        } catch (Exception e) {
            logger.error("❌ [ssoLogin] Exception occurred", e);
            return "redirect:" + loginPageUrl + "?error=sso_failed";
        }
    }

    // ===================================================================
    // SAML CALLBACK - POST MAPPING (WITH DETAILED LOGGING)
    // ===================================================================
    @PostMapping("/callback")
    public void handleSamlCallback(
            @RequestParam(value = "SAMLResponse", required = false) String samlResponse,
            @RequestParam(value = "RelayState", required = false) String relayState,
            HttpServletRequest request,
            HttpServletResponse response) throws IOException {

        logger.info("═══════════════════════════════════════════════════════");
        logger.info("🔄 [handleSamlCallback] SAML CALLBACK RECEIVED");
        logger.info("═══════════════════════════════════════════════════════");

        try {
            Long tenantId = TenantContext.getTenantId();
            logger.info("📋 Tenant ID from context: {}", tenantId);

            if (tenantId == null) {
                logger.error("❌ [handleSamlCallback] No tenant context!");
                response.sendRedirect(loginPageUrl + "?error=sso_callback_failed");
                return;
            }

            if (samlResponse == null || samlResponse.isEmpty()) {
                logger.error("❌ [handleSamlCallback] Missing SAML response");
                response.sendRedirect(loginPageUrl + "?error=missing_saml_response");
                return;
            }

            logger.info("✅ [handleSamlCallback] SAML Response received (length: {})", samlResponse.length());

            try {
                logger.info("📤 [handleSamlCallback] Step 1: Parsing SAML response...");
                Map<String, Object> attributes = samlService.parseSamlResponse(samlResponse);
                logger.info("✅ [handleSamlCallback] SAML response parsed. Attributes count: {}", attributes.size());
                logger.info("📋 [handleSamlCallback] Attributes: {}", attributes.keySet());

                String email = (String) attributes.get("email");
                String name = (String) attributes.getOrDefault("name", "SAML User");

                logger.info("📋 [handleSamlCallback] Extracted - Email: {}, Name: {}", email, name);

                if (email == null || email.isEmpty()) {
                    logger.error("❌ [handleSamlCallback] No email in SAML response!");
                    response.sendRedirect(loginPageUrl + "?error=email_missing");
                    return;
                }

                logger.info("📤 [handleSamlCallback] Step 2: Finding or creating user...");
                User user = findOrCreateUser(email, name, tenantId);
                logger.info("✅ [handleSamlCallback] User: ID={}, Email={}", user.getId(), user.getEmail());

                logger.info("📤 [handleSamlCallback] Step 3: Setting up authentication...");
                setupCompleteAuthentication(user, request, tenantId);

                logger.info("📤 [handleSamlCallback] Step 4: Building redirect URL...");
                String userType = "END_USER";
                if ("ROLE_ADMIN".equals(user.getRole())) {
                    userType = "TENANT_ADMIN";
                }
                if ("ROLE_SUPERADMIN".equals(user.getRole())) {
                    userType = "SUPERADMIN";
                }

                String redirectUrl = buildPostSsoRedirectUrl(request, tenantId, userType);
                logger.info("📤 [handleSamlCallback] Step 5: Sending redirect...");
                logger.info("🎯 [handleSamlCallback] REDIRECTING TO: {}", redirectUrl);

                response.sendRedirect(redirectUrl);
                logger.info("═══════════════════════════════════════════════════════");
                logger.info("✅ [handleSamlCallback] REDIRECT SENT SUCCESSFULLY");
                logger.info("═══════════════════════════════════════════════════════");
                return;

            } catch (Exception e) {
                logger.error("❌ [handleSamlCallback] Exception during processing", e);
                logger.error("❌ Exception message: {}", e.getMessage());
                logger.error("❌ Exception cause: {}", e.getCause());
                e.printStackTrace();
                response.sendRedirect(loginPageUrl + "?error=saml_processing_failed");
                return;
            }

        } catch (Exception e) {
            logger.error("❌ [handleSamlCallback] Outer exception occurred", e);
            e.printStackTrace();
            try {
                response.sendRedirect(loginPageUrl + "?error=sso_callback_failed");
            } catch (IOException ex) {
                logger.error("Failed to redirect after error: {}", ex.getMessage());
            }
        }
    }

    // ===================================================================
    // OAUTH CALLBACK (JWT & OIDC) - GET MAPPING
    // ===================================================================
    @GetMapping("/callback")
    public void handleOAuthCallback(
            @RequestParam(value = "id_token", required = false) String idToken,
            @RequestParam(value = "code", required = false) String authCode,
            @RequestParam(value = "state", required = false) String state,
            @RequestParam(value = "error", required = false) String error,
            @RequestParam(value = "error_description", required = false) String errorDescription,
            HttpServletRequest request,
            HttpServletResponse response) throws IOException {

        logger.info("═══════════════════════════════════════════════════════");
        logger.info("🔄 [handleOAuthCallback] OAUTH CALLBACK RECEIVED");
        logger.info("═══════════════════════════════════════════════════════");

        try {
            Long tenantId = TenantContext.getTenantId();
            logger.info("📋 Tenant ID from context: {}", tenantId);

            if (tenantId == null) {
                logger.error("❌ [handleOAuthCallback] No tenant context!");
                response.sendRedirect(loginPageUrl + "?error=sso_callback_failed");
                return;
            }

            if (error != null) {
                logger.error("❌ [handleOAuthCallback] OAuth error: {} - {}", error, errorDescription);
                response.sendRedirect(loginPageUrl + "?error=sso_auth_failed");
                return;
            }

            String ssoType = determineSsoType(idToken, authCode);
            logger.info("📋 [handleOAuthCallback] SSO Type detected: {}", ssoType);

            if ("JWT".equals(ssoType)) {
                handleJwtCallback(idToken, request, response, tenantId);
            } else if ("OIDC".equals(ssoType)) {
                handleOidcCallback(authCode, state, request, response, tenantId);
            } else {
                logger.error("❌ [handleOAuthCallback] Unknown SSO type");
                response.sendRedirect(loginPageUrl + "?error=unknown_sso_type");
            }

        } catch (Exception e) {
            logger.error("❌ [handleOAuthCallback] Exception occurred", e);
            e.printStackTrace();
            try {
                response.sendRedirect(loginPageUrl + "?error=sso_callback_failed");
            } catch (IOException ex) {
                logger.error("Failed to redirect: {}", ex.getMessage());
            }
        }
    }

    // ===================================================================
    // JWT CALLBACK HANDLER
    // ===================================================================
    private void handleJwtCallback(String idToken, HttpServletRequest request,
                                   HttpServletResponse response, Long tenantId) throws IOException {
        logger.info("═══════════════════════════════════════════════════════");
        logger.info("🔄 [handleJwtCallback] JWT CALLBACK PROCESSING");
        logger.info("═══════════════════════════════════════════════════════");

        if (idToken == null || idToken.isEmpty()) {
            logger.error("❌ [handleJwtCallback] Missing id_token");
            response.sendRedirect(loginPageUrl + "?error=missing_token");
            return;
        }

        try {
            Map<String, Object> claims = ssoService.parseJwtToken(idToken);
            String email = (String) claims.get("email");
            String name = (String) claims.getOrDefault("name", "JWT User");

            logger.info("📋 [handleJwtCallback] Email: {}, Name: {}", email, name);

            if (email == null || email.isEmpty()) {
                logger.error("❌ [handleJwtCallback] No email in JWT token!");
                response.sendRedirect(loginPageUrl + "?error=email_missing");
                return;
            }

            User user = findOrCreateUser(email, name, tenantId);
            setupCompleteAuthentication(user, request, tenantId);

            String userType = "END_USER";
            if ("ROLE_ADMIN".equals(user.getRole())) {
                userType = "TENANT_ADMIN";
            }

            String redirectUrl = buildPostSsoRedirectUrl(request, tenantId, userType);
            logger.info("🎯 [handleJwtCallback] REDIRECTING TO: {}", redirectUrl);
            response.sendRedirect(redirectUrl);

        } catch (Exception e) {
            logger.error("❌ [handleJwtCallback] Exception occurred", e);
            e.printStackTrace();
            response.sendRedirect(loginPageUrl + "?error=jwt_processing_failed");
        }
    }

    // ===================================================================
    // OIDC CALLBACK HANDLER
    // ===================================================================
    private void handleOidcCallback(String authCode, String state, HttpServletRequest request,
                                    HttpServletResponse response, Long tenantId) throws IOException {
        logger.info("═══════════════════════════════════════════════════════");
        logger.info("🔄 [handleOidcCallback] OIDC CALLBACK PROCESSING");
        logger.info("═══════════════════════════════════════════════════════");

        if (authCode == null || authCode.isEmpty()) {
            logger.error("❌ [handleOidcCallback] Missing authorization code");
            response.sendRedirect(loginPageUrl + "?error=missing_code");
            return;
        }

        try {
            logger.info("📤 [handleOidcCallback] Exchanging authorization code for tokens...");
            Map<String, Object> tokenResponse = oidcService.exchangeCodeForToken(authCode);
            String accessToken = (String) tokenResponse.get("access_token");
            logger.info("✅ [handleOidcCallback] Token exchange successful");

            if (accessToken == null || accessToken.isEmpty()) {
                logger.error("❌ [handleOidcCallback] No access token received");
                response.sendRedirect(loginPageUrl + "?error=no_access_token");
                return;
            }

            String idToken = (String) tokenResponse.get("id_token");
            Map<String, Object> userInfo = oidcService.getUserInfo(accessToken);
            String email = extractEmail(userInfo, idToken);
            String name = extractName(userInfo, idToken);

            logger.info("📋 [handleOidcCallback] Email: {}, Name: {}", email, name);

            if (email == null || email.isEmpty()) {
                logger.error("❌ [handleOidcCallback] No email found!");
                response.sendRedirect(loginPageUrl + "?error=email_missing");
                return;
            }

            User user = findOrCreateUser(email, name, tenantId);
            setupCompleteAuthentication(user, request, tenantId);

            String userType = "END_USER";
            if ("ROLE_ADMIN".equals(user.getRole())) {
                userType = "TENANT_ADMIN";
            }

            String redirectUrl = buildPostSsoRedirectUrl(request, tenantId, userType);
            logger.info("🎯 [handleOidcCallback] REDIRECTING TO: {}", redirectUrl);
            response.sendRedirect(redirectUrl);

        } catch (Exception e) {
            logger.error("❌ [handleOidcCallback] Exception occurred", e);
            e.printStackTrace();
            response.sendRedirect(loginPageUrl + "?error=oidc_processing_failed");
        }
    }

    // ===================================================================
    // HELPER METHODS
    // ===================================================================

    private String determineSsoType(String idToken, String authCode) {
        if (idToken != null && !idToken.isEmpty()) {
            return "JWT";
        } else if (authCode != null && !authCode.isEmpty()) {
            return "OIDC";
        }
        return "UNKNOWN";
    }

    private String extractEmail(Map<String, Object> userInfo, String idToken) {
        if (userInfo != null && userInfo.containsKey("email")) {
            return (String) userInfo.get("email");
        }
        if (idToken != null && !idToken.isEmpty()) {
            try {
                Map<String, Object> idTokenClaims = oidcService.parseIdToken(idToken);
                if (idTokenClaims.containsKey("email")) {
                    return (String) idTokenClaims.get("email");
                }
            } catch (Exception e) {
                logger.warn("Could not parse ID token for email");
            }
        }
        return null;
    }

    private String extractName(Map<String, Object> userInfo, String idToken) {
        if (userInfo != null) {
            if (userInfo.containsKey("name")) {
                return (String) userInfo.get("name");
            }
            if (userInfo.containsKey("given_name") && userInfo.containsKey("family_name")) {
                return userInfo.get("given_name") + " " + userInfo.get("family_name");
            }
        }
        if (idToken != null && !idToken.isEmpty()) {
            try {
                Map<String, Object> idTokenClaims = oidcService.parseIdToken(idToken);
                if (idTokenClaims.containsKey("name")) {
                    return (String) idTokenClaims.get("name");
                }
            } catch (Exception e) {
                logger.warn("Could not parse ID token for name");
            }
        }
        return "SSO User";
    }

    private User findOrCreateUser(String email, String name, Long tenantId) {
        logger.info("🔍 [findOrCreateUser] Looking for user: {} in tenant: {}", email, tenantId);

        if (tenantId == null) {
            logger.error("❌ [findOrCreateUser] No tenant context!");
            throw new IllegalStateException("SSO login failed: No tenant context found.");
        }

        Optional<User> existingUser = userRepository.findByEmailAndTenantId(email, tenantId);

        if (existingUser.isPresent()) {
            logger.info("✅ [findOrCreateUser] User found: ID={}", existingUser.get().getId());
            return existingUser.get();
        }

        logger.info("ℹ️ [findOrCreateUser] User not found, creating new user...");

        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> {
                    logger.error("❌ [findOrCreateUser] Tenant not found!");
                    return new IllegalStateException("SSO login failed: Tenant not found.");
                });

        User newUser = new User();
        newUser.setEmail(email);
        newUser.setFullName(name);
        newUser.setPasswordHash("SSO_LOGIN");
        newUser.setRole("ROLE_USER");
        newUser.setTenant(tenant);

        User savedUser = userRepository.save(newUser);
        logger.info("✅ [findOrCreateUser] New user created: ID={}, Email={}", savedUser.getId(), savedUser.getEmail());

        return savedUser;
    }
}