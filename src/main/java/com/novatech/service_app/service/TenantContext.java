package com.novatech.service_app.service;

import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

/**
 * Thread-local and request-scoped storage for the current tenant ID.
 */
public class TenantContext {

    private static final ThreadLocal<Long> CURRENT_TENANT = new ThreadLocal<>();
    private static final String TENANT_ID_ATTRIBUTE = "TENANT_ID";

    public static void setTenantId(Long tenantId) {
        CURRENT_TENANT.set(tenantId);

        // Also store in request attributes for persistence across filters
        try {
            RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
            if (requestAttributes != null) {
                requestAttributes.setAttribute(TENANT_ID_ATTRIBUTE, tenantId, RequestAttributes.SCOPE_REQUEST);
            }
        } catch (Exception e) {
            // Request context not available (e.g., in async threads)
        }
    }

    public static Long getTenantId() {
        Long tenantId = CURRENT_TENANT.get();

        // If ThreadLocal is null, try request attributes
        if (tenantId == null) {
            try {
                RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
                if (requestAttributes != null) {
                    tenantId = (Long) requestAttributes.getAttribute(TENANT_ID_ATTRIBUTE, RequestAttributes.SCOPE_REQUEST);
                }
            } catch (Exception e) {
                // Request context not available
            }
        }

        return tenantId;
    }

    public static void clear() {
        CURRENT_TENANT.remove();

        try {
            RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
            if (requestAttributes != null) {
                requestAttributes.removeAttribute(TENANT_ID_ATTRIBUTE, RequestAttributes.SCOPE_REQUEST);
            }
        } catch (Exception e) {
            // Request context not available
        }
    }

    /**
     * Check if we're in superadmin context (no tenant set).
     */
    public static boolean isSuperAdminContext() {
        return getTenantId() == null;
    }
}