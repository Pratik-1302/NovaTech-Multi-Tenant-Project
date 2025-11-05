package com.novatech.service_app.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * Entity to store SSO configurations (JWT, OIDC, SAML)
 * Replaces hardcoded application.properties values
 */
@Entity
@Table(name = "sso_configurations")
public class SsoConfiguration {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * Type of SSO: JWT, OIDC, or SAML
     */
    @Column(name = "sso_type", nullable = false, unique = true)
    private String ssoType; // "JWT", "OIDC", "SAML"

    /**
     * Provider name (e.g., "miniOrange JWT", "Okta OIDC")
     */
    @Column(name = "provider_name")
    private String providerName;

    /**
     * OAuth/OIDC Client ID
     */
    @Column(name = "client_id", length = 500)
    private String clientId;

    /**
     * OAuth/OIDC Client Secret
     * TODO: Encrypt this in production
     */
    @Column(name = "client_secret", length = 1000)
    private String clientSecret;

    /**
     * Authorization endpoint URL (for initial redirect)
     */
    @Column(name = "authorization_endpoint", length = 1000)
    private String authorizationEndpoint;

    /**
     * Token endpoint URL (for OIDC code exchange)
     */
    @Column(name = "token_endpoint", length = 1000)
    private String tokenEndpoint;

    /**
     * UserInfo endpoint URL (for getting user details)
     */
    @Column(name = "userinfo_endpoint", length = 1000)
    private String userinfoEndpoint;

    /**
     * Redirect URI (callback URL)
     */
    @Column(name = "redirect_uri", length = 500)
    private String redirectUri;

    /**
     * Certificate path for JWT verification (optional)
     */
    @Column(name = "certificate_path", length = 500)
    private String certificatePath;

    /**
     * Domain (for miniOrange or similar)
     */
    @Column(name = "domain", length = 500)
    private String domain;

    /**
     * Issuer URL (for OIDC/SAML validation)
     */
    @Column(name = "issuer", length = 500)
    private String issuer;

    /**
     * Scopes for OIDC (space-separated: "openid profile email")
     */
    @Column(name = "scopes", length = 500)
    private String scopes;

    /**
     * Is this SSO configuration enabled?
     */
    @Column(name = "enabled", nullable = false)
    private boolean enabled = false;

    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    // ============================================================
    //                        Lifecycle Hooks
    // ============================================================
    @PrePersist
    protected void onCreate() {
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        this.updatedAt = LocalDateTime.now();
    }

    // ============================================================
    //                        Constructors
    // ============================================================
    public SsoConfiguration() {}

    public SsoConfiguration(String ssoType, String providerName, boolean enabled) {
        this.ssoType = ssoType;
        this.providerName = providerName;
        this.enabled = enabled;
    }

    // ============================================================
    //                        Getters & Setters
    // ============================================================
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getSsoType() {
        return ssoType;
    }

    public void setSsoType(String ssoType) {
        this.ssoType = ssoType != null ? ssoType.toUpperCase() : null;
    }

    public String getProviderName() {
        return providerName;
    }

    public void setProviderName(String providerName) {
        this.providerName = providerName;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getAuthorizationEndpoint() {
        return authorizationEndpoint;
    }

    public void setAuthorizationEndpoint(String authorizationEndpoint) {
        this.authorizationEndpoint = authorizationEndpoint;
    }

    public String getTokenEndpoint() {
        return tokenEndpoint;
    }

    public void setTokenEndpoint(String tokenEndpoint) {
        this.tokenEndpoint = tokenEndpoint;
    }

    public String getUserinfoEndpoint() {
        return userinfoEndpoint;
    }

    public void setUserinfoEndpoint(String userinfoEndpoint) {
        this.userinfoEndpoint = userinfoEndpoint;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public String getCertificatePath() {
        return certificatePath;
    }

    public void setCertificatePath(String certificatePath) {
        this.certificatePath = certificatePath;
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getScopes() {
        return scopes;
    }

    public void setScopes(String scopes) {
        this.scopes = scopes;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    // ============================================================
    //                        Utility Methods
    // ============================================================
    @Override
    public String toString() {
        return "SsoConfiguration{" +
                "id=" + id +
                ", ssoType='" + ssoType + '\'' +
                ", providerName='" + providerName + '\'' +
                ", enabled=" + enabled +
                ", authorizationEndpoint='" + authorizationEndpoint + '\'' +
                '}';
    }
}
//working-version