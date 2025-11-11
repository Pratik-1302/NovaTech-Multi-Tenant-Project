# 🚀 NovaTech Multi-Tenant Service Platform

<div align="center">

![Java](https://img.shields.io/badge/Java-21-orange?style=for-the-badge&logo=openjdk)
![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.5.7-brightgreen?style=for-the-badge&logo=spring)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-14+-blue?style=for-the-badge&logo=postgresql)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

**A production-ready, multi-tenant SaaS platform with dynamic SSO configuration and subdomain-based tenant isolation.**

[Features](#key-features) • [Quick Start](#installation) • [Architecture](#architecture) • [Documentation](#multi-tenant-flow)

</div>

---

## 📋 Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Tech Stack](#tech-stack)
- [Architecture](#architecture)
- [Installation](#installation)
- [Multi-Tenant Flow](#multi-tenant-flow)
- [Contributing](#contributing)
- [License](#license)

---

## 🌟 Overview

NovaTech is an enterprise-grade **multi-tenant SaaS platform** built with Spring Boot that provides:

- 🏢 **Subdomain-based tenant isolation** (e.g., `acme.yourdomain.com`)
- 🔐 **Dynamic SSO configuration** (JWT, OIDC, SAML 2.0)
- 👥 **Three-tier user hierarchy** (Superadmin → Tenant Admin → End Users)
- 🎨 **Modern glassmorphism UI** with Tailwind CSS
- 🔒 **Enterprise security** with Spring Security 6
- 📊 **Real-time tenant management** dashboard

---

## ✨ Key Features

### 🏗️ **Multi-Tenancy Architecture**

- **Subdomain-based tenant routing** with automatic context resolution
- **Shared database with tenant isolation** using discriminator columns
- **ThreadLocal tenant context** for seamless data filtering
- **Cascade tenant deletion** with referential integrity

### 🔐 **Advanced Authentication**

- **Multiple SSO protocols**: JWT, OpenID Connect (OIDC), SAML 2.0
- **Database-driven SSO config**: No application restart required
- **Role-based access control**: `SUPERADMIN` → `ADMIN` → `USER`
- **Session-based authentication** with CSRF protection

### 🎨 **Modern User Interface**

- **Glassmorphism design** with backdrop blur effects
- **Responsive layouts** optimized for desktop and mobile
- **Smooth animations** and micro-interactions
- **Real-time validation** with error handling

### 🛠️ **Developer Experience**

- **Clean architecture** with separation of concerns
- **Comprehensive logging** for debugging
- **Hot reload support** during development
- **RESTful API design** for extensibility

---

## 🛠️ Tech Stack

### **Backend**
| Technology | Version | Purpose |
|------------|---------|---------|
| ![Java](https://img.shields.io/badge/-Java-007396?style=flat-square&logo=openjdk) | 21 | Core programming language |
| ![Spring Boot](https://img.shields.io/badge/-Spring%20Boot-6DB33F?style=flat-square&logo=spring) | 3.5.7 | Application framework |
| ![Spring Security](https://img.shields.io/badge/-Spring%20Security-6DB33F?style=flat-square&logo=spring) | 6.x | Authentication & authorization |
| ![Spring Data JPA](https://img.shields.io/badge/-Spring%20Data%20JPA-6DB33F?style=flat-square&logo=spring) | 3.x | Database abstraction layer |
| ![Hibernate](https://img.shields.io/badge/-Hibernate-59666C?style=flat-square&logo=hibernate) | 6.x | ORM framework |

### **Database**
| Technology | Version | Purpose |
|------------|---------|---------|
| ![PostgreSQL](https://img.shields.io/badge/-PostgreSQL-336791?style=flat-square&logo=postgresql) | 14+ | Primary database |

### **Frontend**
| Technology | Version | Purpose |
|------------|---------|---------|
| ![Thymeleaf](https://img.shields.io/badge/-Thymeleaf-005F0F?style=flat-square&logo=thymeleaf) | 3.1.x | Server-side rendering |
| ![Tailwind CSS](https://img.shields.io/badge/-Tailwind%20CSS-38B2AC?style=flat-square&logo=tailwind-css) | 3.x | Utility-first CSS framework |
| ![JavaScript](https://img.shields.io/badge/-JavaScript-F7DF1E?style=flat-square&logo=javascript) | ES6+ | Client-side interactivity |

### **SSO Libraries**
| Technology | Version | Purpose |
|------------|---------|---------|
| ![JJWT](https://img.shields.io/badge/-JJWT-000000?style=flat-square) | 0.11.5 | JWT parsing & validation |
| ![JAXB](https://img.shields.io/badge/-JAXB-007396?style=flat-square) | 4.0.0 | SAML XML processing |
| ![WebFlux](https://img.shields.io/badge/-WebFlux-6DB33F?style=flat-square&logo=spring) | 3.x | OIDC HTTP client |

---

## 🏛️ Architecture

### **System Architecture Diagram**

```
┌─────────────────────────────────────────────────────────────┐
│                    Client Browser                           │
└──────────────┬──────────────────────────────┬───────────────┘
               │                              │
               │ acme.localhost               │ localhost
               │                              │
┌──────────────▼──────────────┐  ┌───────────▼──────────────┐
│   Tenant Subdomain          │  │  Superadmin Portal       │
│   (Tenant Admin + Users)    │  │  (System Management)     │
└──────────────┬──────────────┘  └───────────┬──────────────┘
               │                              │
               └──────────────┬───────────────┘
                              │
                   ┌──────────▼──────────┐
                   │   TenantFilter      │
                   │  (Subdomain Parser) │
                   └──────────┬──────────┘
                              │
                   ┌──────────▼──────────┐
                   │  Spring Security    │
                   │  (Authentication)   │
                   └──────────┬──────────┘
                              │
               ┌──────────────┼──────────────┐
               │              │              │
    ┌──────────▼─────┐ ┌─────▼──────┐ ┌────▼─────────┐
    │ UserService    │ │TenantService│ │ SSOService   │
    │ (User CRUD)    │ │(Tenant CRUD)│ │ (JWT/OIDC/   │
    │                │ │             │ │  SAML)       │
    └──────────┬─────┘ └─────┬──────┘ └────┬─────────┘
               │              │              │
               └──────────────┼──────────────┘
                              │
                   ┌──────────▼──────────┐
                   │   PostgreSQL DB     │
                   │  ┌──────────────┐   │
                   │  │   tenants    │   │
                   │  │   users      │   │
                   │  │   sso_config │   │
                   │  └──────────────┘   │
                   └─────────────────────┘
```

### **Tenant Isolation Flow**

```
1. User → http://acme.localhost:8080/login
              │
2. TenantFilter extracts "acme" subdomain
              │
3. Lookup Tenant ID from database (tenant_id = 5)
              │
4. TenantContext.setTenantId(5) [ThreadLocal]
              │
5. Spring Security authenticates user
              │
6. All queries automatically filtered by tenant_id = 5
```

---

## 🚀 Installation

### **Prerequisites**

- ☕ Java 21 or higher ([Download](https://adoptium.net/))
- 🐘 PostgreSQL 14+ ([Download](https://www.postgresql.org/download/))
- 📦 Maven 3.8+ (or use included `mvnw`)
- 🌐 Modern web browser (Chrome, Firefox, Edge)

### **Step 1: Clone Repository**

```bash
git clone https://github.com/yourusername/novatech-service-app.git
cd novatech-service-app
```

### **Step 2: Database Setup**

```sql
-- Create database
CREATE DATABASE db;

-- Create user (optional)
CREATE USER db_user WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE db TO db_user;
```

### **Step 3: Configure Application**

Edit `src/main/resources/application.properties`:

```properties
# Database Configuration
spring.datasource.url=
spring.datasource.username=
spring.datasource.password=

# Hibernate DDL (will auto-create tables)
spring.jpa.hibernate.ddl-auto=update
```

### **Step 4: Build & Run**

```bash
# Using Maven Wrapper (Recommended)
./mvnw clean install
./mvnw spring-boot:run

# Or using installed Maven
mvn clean install
mvn spring-boot:run
```

The application will start on **http://localhost:8080**

---

## 🔄 Multi-Tenant Flow

### **Tenant Isolation Flow**

```
1. User → http://acme.localhost:8080/login
2. TenantFilter extracts "acme" subdomain
3. Lookup Tenant ID from database
4. TenantContext.setTenantId() [ThreadLocal]
5. Spring Security authenticates user
6. All queries automatically filtered by tenant_id
```

---

## 🤝 Contributing

We welcome contributions! Please follow these guidelines:

### **Development Setup**

```bash
git clone https://github.com/yourusername/novatech-service-app.git
cd novatech-service-app
./mvnw clean install
```

### **Branch Naming**

- `feature/your-feature-name` - New features
- `bugfix/issue-description` - Bug fixes
- `hotfix/critical-fix` - Production hotfixes

### **Commit Messages**

```
feat: Add tenant deletion cascade
fix: Resolve subdomain parsing for hyphenated names
docs: Update README with SSO examples
style: Format code according to checkstyle
```

### **Pull Request Process**

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to your fork
5. Open a Pull Request with description

---

## 📄 License

This project is licensed under the **MIT License**.

```
MIT License

Copyright (c) 2025 NovaTech

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

---

## 📞 Support

### **Documentation**
- [Spring Boot Docs](https://docs.spring.io/spring-boot/)
- [Spring Security Reference](https://docs.spring.io/spring-security/)
- [Thymeleaf Guide](https://www.thymeleaf.org/documentation.html)

### **Maintainers**
- [@Pratik-1302](https://github.com/Pratik-1302) - Lead Developer

---

## 🎯 Roadmap

### **Version 2.0 (Planned)**
- [ ] Multi-database support (MySQL, Oracle)
- [ ] Docker containerization
- [ ] Kubernetes deployment manifests
- [ ] GraphQL API
- [ ] Tenant-specific themes
- [ ] Advanced analytics dashboard

### **Version 3.0 (Future)**
- [ ] Microservices architecture
- [ ] Event-driven messaging (Kafka)
- [ ] Mobile app (React Native)
- [ ] AI-powered insights

---

<div align="center">

**Built by Pratik Kape**

[⬆ Back to Top](#-novatech-multi-tenant-service-platform)

</div>
