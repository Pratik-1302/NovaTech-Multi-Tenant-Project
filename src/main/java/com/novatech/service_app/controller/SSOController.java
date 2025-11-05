package com.novatech.service_app.controller;

import com.novatech.service_app.entity.User;
import com.novatech.service_app.repository.UserRepository;
import com.novatech.service_app.service.SSOService;
import com.novatech.service_app.service.OidcService;
import com.novatech.service_app.service.SamlService; // ✅ IMPORT NEW SERVICE
import com.novatech.service_app.service.SsoManagementService;
import jakarta.servlet.http.HttpServletRequest;
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
import org.springframework.web.bind.annotation.PostMapping; // ✅ IMPORT POSTMAPPING
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

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

    // ✅ AUTOWIRE NEW SERVICE AT CLASS LEVEL
    @Autowired
    private SamlService samlService;

    @Autowired
    private SsoManagementService ssoManagementService;

    @Autowired
    private UserRepository userRepository;

    @Value("${app.homepage-url:http://localhost:8080/home}")
    private String homePageUrl;

    @Value("${app.logout-success-url:http://localhost:8080/login}")
    private String loginPageUrl;

    @GetMapping("/login")
    public String ssoLogin(@RequestParam(value = "type", defaultValue = "jwt") String ssoType) {
        try {
            logger.info("=== SSO LOGIN INITIATED ===");
            logger.info("SSO Type: {}", ssoType.toUpperCase());
            ssoType = ssoType.toUpperCase();
            if (!ssoManagementService.isSsoTypeEnabled(ssoType)) {
                logger.error("❌ SSO type {} is not enabled", ssoType);
                return "redirect:" + loginPageUrl + "?error=sso_disabled";
            }

            String authorizationUrl = ssoService.getAuthorizationUrl(ssoType);
            logger.info("➡️ Redirecting user to {} SSO login page", ssoType);
            return "redirect:" + authorizationUrl;
        } catch (IllegalStateException e) {
            logger.error("❌ SSO configuration error: {}", e.getMessage());
            return "redirect:" + loginPageUrl + "?error=sso_config_error";
        } catch (Exception e) {
            logger.error("❌ SSO login failed: {}", e.getMessage(), e);
            return "redirect:" + loginPageUrl + "?error=sso_failed";
        }
    }

    /**
     * ✅ UPDATED: Handles both GET (for OIDC/JWT) and POST (for SAML)
     */
    @RequestMapping("/callback")
    public String handleCallback(
            @RequestParam(value = "id_token", required = false) String idToken,
            @RequestParam(value = "code", required = false) String authCode,
            @RequestParam(value = "state", required = false) String state,
            @RequestParam(value = "SAMLResponse", required = false) String samlResponse,
            @RequestParam(value = "error", required = false) String error,
            @RequestParam(value = "error_description", required = false) String errorDescription,
            HttpServletRequest request) {

        try {
            logger.info("=== SSO CALLBACK RECEIVED ===");
            if (error != null) {
                logger.error("❌ OAuth error: {} - {}", error, errorDescription);
                return "redirect:" + loginPageUrl + "?error=sso_auth_failed";
            }

            String ssoType = determineSsoType(idToken, authCode, samlResponse);
            logger.info("Detected SSO Type: {}", ssoType);

            switch (ssoType) {
                case "JWT":
                    return handleJwtCallback(idToken, request);
                case "OIDC":
                    return handleOidcCallback(authCode, state, request);
                case "SAML":
                    return handleSamlCallback(samlResponse, request);
                default:
                    logger.error("❌ Unknown SSO callback type. No id_token, code, or SAMLResponse found.");
                    return "redirect:" + loginPageUrl + "?error=unknown_sso_type";
            }

        } catch (Exception e) {
            logger.error("❌ SSO callback failed: {}", e.getMessage(), e);
            return "redirect:" + loginPageUrl + "?error=sso_callback_failed";
        }
    }

    private String determineSsoType(String idToken, String authCode, String samlResponse) {
        if (idToken != null && !idToken.isEmpty()) {
            return "JWT";
        } else if (authCode != null && !authCode.isEmpty()) {
            return "OIDC";
        } else if (samlResponse != null && !samlResponse.isEmpty()) {
            return "SAML";
        }
        return "UNKNOWN";
    }

    private String handleJwtCallback(String idToken, HttpServletRequest request) throws Exception {
        logger.info("=== PROCESSING JWT CALLBACK ===");
        if (idToken == null || idToken.isEmpty()) {
            logger.error("❌ Missing id_token in JWT callback");
            return "redirect:" + loginPageUrl + "?error=missing_token";
        }
        Map<String, Object> claims = ssoService.parseJwtToken(idToken);
        String email = (String) claims.get("email");
        String name = (String) claims.getOrDefault("name", "SSO User");
        if (email == null || email.isEmpty()) {
            logger.error("❌ No email found in JWT token!");
            return "redirect:" + loginPageUrl + "?error=email_missing";
        }
        logger.info("✅ JWT verified. Email: {}, Name: {}", email, name);
        User user = findOrCreateUser(email, name);
        authenticateUser(user, request);
        logger.info("✅ JWT SSO login successful for: {}", user.getEmail());
        logger.info("➡️ Redirecting to homepage: {}", homePageUrl);
        return "redirect:" + homePageUrl;
    }

    private String handleOidcCallback(String authCode, String state, HttpServletRequest request) throws Exception {
        logger.info("=== PROCESSING OIDC CALLBACK ===");
        if (authCode == null || authCode.isEmpty()) {
            logger.error("❌ Missing authorization code in OIDC callback");
            return "redirect:" + loginPageUrl + "?error=missing_code";
        }
        try {
            logger.info("📤 Step 1: Exchanging code for token...");
            Map<String, Object> tokenResponse = oidcService.exchangeCodeForToken(authCode);
            String accessToken = (String) tokenResponse.get("access_token");
            String idToken = (String) tokenResponse.get("id_token");
            logger.info("✅ Token exchange successful");
            if (accessToken == null || accessToken.isEmpty()) {
                logger.error("❌ No access token received");
                return "redirect:" + loginPageUrl + "?error=no_access_token";
            }
            logger.info("📤 Step 2: Fetching user info...");
            Map<String, Object> userInfo = oidcService.getUserInfo(accessToken);
            String email = extractEmail(userInfo, idToken);
            String name = extractName(userInfo, idToken);
            if (email == null || email.isEmpty()) {
                logger.error("❌ No email found in OIDC response!");
                return "redirect:" + loginPageUrl + "?error=email_missing";
            }
            logger.info("✅ OIDC user info retrieved. Email: {}, Name: {}", email, name);
            User user = findOrCreateUser(email, name);
            authenticateUser(user, request);
            logger.info("✅ OIDC SSO login successful for: {}", user.getEmail());
            logger.info("➡️ Redirecting to homepage: {}", homePageUrl);
            return "redirect:" + homePageUrl;
        } catch (Exception e) {
            logger.error("❌ OIDC callback processing failed: {}", e.getMessage(), e);
            return "redirect:" + loginPageUrl + "?error=oidc_processing_failed";
        }
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
                logger.warn("⚠️ Could not parse ID token for email: {}", e.getMessage());
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
                logger.warn("⚠️ Could not parse ID token for name: {}", e.getMessage());
            }
        }
        return "OIDC User";
    }

    /**
     * ✅ UPDATED: Handle SAML SSO callback
     */
    private String handleSamlCallback(String samlResponse, HttpServletRequest request) throws Exception {
        logger.info("=== PROCESSING SAML CALLBACK ===");
        if (samlResponse == null || samlResponse.isEmpty()) {
            logger.error("❌ Missing SAML response");
            return "redirect:" + loginPageUrl + "?error=missing_saml_response";
        }

        try {
            // ✅ Parse and VALIDATE SAML response
            Map<String, Object> attributes = samlService.parseSamlResponse(samlResponse);

            // Extract user details
            String email = (String) attributes.get("email");
            String name = (String) attributes.getOrDefault("name", "SAML User");

            if (email == null || email.isEmpty()) {
                logger.error("❌ No email found in SAML response!");
                logger.error("Available attributes: {}", attributes.keySet());
                return "redirect:" + loginPageUrl + "?error=email_missing";
            }

            logger.info("✅ SAML response parsed and validated. Email: {}, Name: {}", email, name);

            // ✅ Fetch or create user
            User user = findOrCreateUser(email, name);

            // ✅ Authenticate user in Spring Security
            authenticateUser(user, request);

            logger.info("✅ SAML SSO login successful for: {}", user.getEmail());
            logger.info("➡️ Redirecting to homepage: {}", homePageUrl);

            return "redirect:" + homePageUrl;

        } catch (Exception e) {
            logger.error("❌ SAML callback processing failed: {}", e.getMessage(), e);
            // This is the redirect you are probably seeing
            return "redirect:" + loginPageUrl + "?error=saml_processing_failed";
        }
    }

    private User findOrCreateUser(String email, String name) {
        Optional<User> existingUser = userRepository.findByEmail(email);
        return existingUser.orElseGet(() -> {
            User newUser = new User();
            newUser.setEmail(email);
            newUser.setFullName(name);
            newUser.setPasswordHash("SSO_LOGIN");
            newUser.setRole("ROLE_USER");
            logger.info("🆕 Creating new SSO user: {}", email);
            return userRepository.save(newUser);
        });
    }

    private void authenticateUser(User user, HttpServletRequest request) {
        UserDetails userDetails = org.springframework.security.core.userdetails.User
                .withUsername(user.getEmail())
                .password("")
                .roles(user.getRole().replace("ROLE_", ""))
                .build();
        UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authToken);
        HttpSession session = request.getSession(true);
        session.setAttribute("loggedInUser", user);
        session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());
        logger.info("✅ User authenticated: {}", user.getEmail());
    }
}