package com.novatech.service_app.service;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;

/**
 * Custom UserDetails implementation that stores additional tenant information.
 */
public class CustomUserDetails implements UserDetails {

    private final String email;
    private final String passwordHash;
    private final String role;
    private final Long userId;
    private final Long tenantId;
    private final String userType; // SUPERADMIN, TENANT_ADMIN, END_USER
    private final String displayName;

    public CustomUserDetails(String email, String passwordHash, String role,
                             Long userId, Long tenantId, String userType, String displayName) {
        this.email = email;
        this.passwordHash = passwordHash;
        this.role = role;
        this.userId = userId;
        this.tenantId = tenantId;
        this.userType = userType;
        this.displayName = displayName;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singletonList(new SimpleGrantedAuthority(role));
    }

    @Override
    public String getPassword() {
        return passwordHash;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    // Custom getters
    public Long getUserId() {
        return userId;
    }

    public Long getTenantId() {
        return tenantId;
    }

    public String getUserType() {
        return userType;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getRole() {
        return role;
    }
}