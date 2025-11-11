package com.novatech.service_app.config;

import com.novatech.service_app.entity.Tenant;
import com.novatech.service_app.service.TenantContext;
import com.novatech.service_app.service.TenantService;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Optional;

/**
 * ✅ PRODUCTION-READY Filter
 * - Handles localhost subdomains (development)
 * - Handles pratiktech.cloud and subdomains (production)
 * - Handles custom domain variations
 */
@Component
public class TenantFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(TenantFilter.class);
    private static final String TENANT_ID_ATTRIBUTE = "TENANT_ID";

    @Autowired
    private TenantService tenantService;

    @Value("${app.domain:localhost}")
    private String appDomain;

    @Value("${app.scheme:http}")
    private String appScheme;

    @Value("${app.port:8080}")
    private String appPort;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        String serverName = httpRequest.getServerName();
        int serverPort = httpRequest.getServerPort();

        logger.debug("🔍 TenantFilter - Processing request for host: {}:{}", serverName, serverPort);

        // ===================================================================
        // CASE 1: Superadmin Context (localhost or main domain)
        // ===================================================================
        if (isSuperadminHost(serverName)) {
            logger.debug("✅ Superadmin context detected for host: {}", serverName);
            TenantContext.clear();
            httpRequest.setAttribute(TENANT_ID_ATTRIBUTE, null);
            chain.doFilter(request, response);
            return;
        }

        // ===================================================================
        // CASE 2: Tenant Subdomain Context
        // ===================================================================
        String subdomain = extractSubdomain(serverName);
        if (subdomain != null && !subdomain.isEmpty()) {
            Optional<Tenant> tenant = tenantService.getTenantBySubdomain(subdomain);

            if (tenant.isPresent()) {
                Long tenantId = tenant.get().getId();
                TenantContext.setTenantId(tenantId);
                httpRequest.setAttribute(TENANT_ID_ATTRIBUTE, tenantId);
                logger.debug("✅ Tenant context set: {} (ID: {})", subdomain, tenantId);
                chain.doFilter(request, response);
                return;
            } else {
                logger.warn("⚠️ Subdomain found but tenant not registered: {}", subdomain);
            }
        }

        // ===================================================================
        // CASE 3: Invalid Hostname - Redirect to Main Domain
        // ===================================================================
        logger.warn("⚠️ Invalid hostname/subdomain: {}. Redirecting to main domain.", serverName);
        String redirectUrl = buildMainDomainUrl(httpRequest);
        httpResponse.sendRedirect(redirectUrl);
    }

    /**
     * Determines if the hostname is for superadmin (no tenant)
     */
    private boolean isSuperadminHost(String serverName) {
        // Development: localhost (with or without port)
        if (serverName.startsWith("localhost")) {
            return true;
        }

        // Production: main domain only (no subdomain)
        // Example: pratiktech.cloud or www.pratiktech.cloud
        if (serverName.equals(appDomain) || serverName.equals("www." + appDomain)) {
            return true;
        }

        return false;
    }

    /**
     * Extracts subdomain from hostname
     * Examples:
     * - acme.localhost:8080 -> acme
     * - acme.localhost -> acme
     * - acme.pratiktech.cloud -> acme
     * - pratiktech.cloud -> null
     * - www.pratiktech.cloud -> null
     */
    private String extractSubdomain(String serverName) {
        // Remove port if present
        String hostOnly = serverName.contains(":") ? serverName.split(":")[0] : serverName;

        // If it's localhost, extract subdomain before the dot
        if (hostOnly.contains("localhost")) {
            String[] parts = hostOnly.split("\\.");
            return parts.length > 1 ? parts[0] : null;
        }

        // If it's production domain (e.g., pratiktech.cloud)
        if (hostOnly.endsWith("." + appDomain)) {
            // Extract everything before the app domain
            String subdomain = hostOnly.substring(0, hostOnly.length() - appDomain.length() - 1);
            // Don't treat "www" as a tenant
            if ("www".equals(subdomain)) {
                return null;
            }
            return subdomain.isEmpty() ? null : subdomain;
        }

        return null;
    }

    /**
     * Builds the main domain URL for redirects
     */
    private String buildMainDomainUrl(HttpServletRequest request) {
        String scheme = request.getScheme();

        // For HTTPS, don't include port
        if ("https".equals(scheme)) {
            return "https://" + appDomain;
        }

        // For HTTP, include port if not default
        int port = request.getServerPort();
        String portString = (port == 80) ? "" : ":" + port;
        return "http://" + appDomain + portString;
    }

    @Override
    public void init(FilterConfig config) {
    }

    @Override
    public void destroy() {
    }
}