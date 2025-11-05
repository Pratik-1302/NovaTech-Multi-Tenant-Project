package com.novatech.service_app.config;

import com.novatech.service_app.entity.Tenant;
import com.novatech.service_app.service.TenantContext;
import com.novatech.service_app.service.TenantService;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse; // 1. ADD THIS IMPORT
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Optional;

/**
 * Filter that extracts subdomain from request and sets tenant context.
 * Runs on every HTTP request BEFORE security filters.
 *
 * [REWRITTEN]
 * - Allows 'localhost' and 'login.localhost' for Superadmin.
 * - Redirects any invalid/unknown subdomains to 'http://localhost:8080'.
 */
@Component
public class TenantFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(TenantFilter.class);
    private static final String TENANT_ID_ATTRIBUTE = "TENANT_ID";

    @Autowired
    private TenantService tenantService;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response; // 2. GET THE HTTP RESPONSE
        String serverName = httpRequest.getServerName();

        logger.debug("🔍 TenantFilter - Processing request for: {}", serverName);

        // ===================================================================
        // CASE 1: Superadmin Context
        // ===================================================================
        if (serverName.equals("localhost") || serverName.equals("login.localhost")) {
            logger.debug("✅ Superadmin context for: {}", serverName);
            TenantContext.clear();
            httpRequest.setAttribute(TENANT_ID_ATTRIBUTE, null);
            chain.doFilter(request, response); // Continue to the application
            return;
        }

        // ===================================================================
        // CASE 2: Tenant Context (must have a valid subdomain)
        // ===================================================================
        String[] parts = serverName.split("\\.");
        if (parts.length > 1) { // Check if there is a subdomain part
            String subdomain = parts[0];
            Optional<Tenant> tenant = tenantService.getTenantBySubdomain(subdomain);

            // 2a: Valid Tenant
            if (tenant.isPresent()) {
                Long tenantId = tenant.get().getId();
                TenantContext.setTenantId(tenantId);
                httpRequest.setAttribute(TENANT_ID_ATTRIBUTE, tenantId);
                logger.debug("✅ Tenant context set: {} (ID: {})", subdomain, tenantId);
                chain.doFilter(request, response); // Continue to the application
                return;
            }
        }

        // ===================================================================
        // CASE 3: Invalid Hostname or Subdomain (Your New Rule)
        // ===================================================================
        // If we're here, it's not superadmin and not a valid tenant.
        logger.warn("⚠️ Invalid hostname/subdomain: {}. Redirecting to localhost.", serverName);

        // Reconstruct the full redirect URL (handling http/https and port)
        String scheme = httpRequest.getScheme(); // http
        String port = (httpRequest.getServerPort() == 80 || httpRequest.getServerPort() == 443) ? "" : ":" + httpRequest.getServerPort();

        // We redirect to localhost, but keep the port and path
        // e.g., http://dinesh.localhost:8080/some/path -> http://localhost:8080/some/path
        String redirectUrl = scheme + "://localhost" + port + httpRequest.getRequestURI();

        // For simple cases, just redirect to the root
        // httpResponse.sendRedirect(scheme + "://localhost" + port);

        // Per your request, redirect to the root of localhost
        httpResponse.sendRedirect(scheme + "://localhost" + port);

        // We STOP the filter chain here. The request will not proceed.
    }

    // This helper method is no longer needed as the logic is in doFilter
    // private String extractSubdomain(String serverName) { ... }
}