package com.novatech.service_app.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * Represents a tenant (customer organization) in the multi-tenant system.
 * Each tenant has their own subdomain and admin credentials.
 */
@Entity
@Table(name = "tenants")
public class Tenant {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false, unique = true)
    private String email;

//    @Column(name = "password_hash", nullable = false)
//    private String passwordHash;

    @Column(nullable = false, unique = true)
    private String subdomain;

    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    /**
     * Transient plain-text password (not persisted)
     */
    @Transient
    private String password;

    // ============================================================
    //                        Constructors
    // ============================================================
    public Tenant() {}

    public Tenant(String name, String email, String password, String subdomain) {
        this.name = name;
        this.email = email;
        this.password = password;
        this.subdomain = subdomain;
    }

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
    //                        Getters & Setters
    // ============================================================
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email != null ? email.trim().toLowerCase() : null;
    }

//    public String getPasswordHash() {
//        return passwordHash;
//    }
//
//    public void setPasswordHash(String passwordHash) {
//        this.passwordHash = passwordHash;
//    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getSubdomain() {
        return subdomain;
    }

    public void setSubdomain(String subdomain) {
        this.subdomain = subdomain != null ? subdomain.trim().toLowerCase() : null;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(LocalDateTime updatedAt) {
        this.updatedAt = updatedAt;
    }

    @Override
    public String toString() {
        return "Tenant{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", email='" + email + '\'' +
                ", subdomain='" + subdomain + '\'' +
                ", createdAt=" + createdAt +
                '}';
    }
}