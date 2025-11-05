Dynamic Multi-Protocol SSO Management System

This is a production-ready Spring Boot application that replaces static, hardcoded SSO configurations with a fully dynamic, database-driven management system. An admin can log in to a secure dashboard to configure, enable, and disable multiple SSO protocols (JWT, OIDC, SAML) in real-time without requiring an application restart.

The login page is 100% dynamic, querying the database to show only the authentication methods that are currently active.

🚀 Core Features

Dynamic SSO Configuration: Configure all SSO provider settings (Endpoints, Client IDs, Secrets, Certificates) from a secure admin UI.

Database-Driven: All settings are stored in a PostgreSQL database, not in .properties files.

Multi-Protocol Support:

JWT: (Token-based)

OIDC: (Authorization Code Flow)

SAML 2.0: (SP-Initiated Flow with POST Binding)

Real-Time Toggling: Enable or disable any SSO provider instantly with a toggle switch. No application restarts needed.

Dynamic Login Page: The user login page automatically queries the database and only renders buttons for SSO providers that are currently enabled.

Full Admin Dashboard: A complete dashboard for managing users (CRUD) and all SSO settings.

Secure Role Hierarchy:

ROLE_SUPER_ADMIN: An "untouchable" root account that cannot be edited or deleted by anyone (even itself).

ROLE_ADMIN: Can manage all users and SSO settings, but cannot modify the Super Admin.

ROLE_USER: Standard user role.

💻 Tech Stack

Backend: Spring Boot 3.x

Language: Java 21

Security: Spring Security 6

Database: Spring Data JPA with PostgreSQL

Frontend: Thymeleaf with Tailwind CSS

Libraries:

jjwt (for JWT parsing)

JAXB (for SAML XML parsing)

⚙️ How It Works: The Authentication Flow

User Visits Login Page (/login):

AuthController calls SsoManagementService.findByEnabledTrue().

The service queries the sso_configurations table.

The login.html template receives a list of active providers (e.g., "SAML", "OIDC") and renders a button for each one.

User Clicks an SSO Button (e.g., "Login with SAML"):

A request hits SSOController at /sso/login?type=SAML.

SSOService looks up the SAML config (SSO URL, Issuer) from the database.

The user is redirected to the Identity Provider (e.g., miniOrange).

User Authenticates at IdP:

The IdP authenticates the user.

The IdP sends the response to the application's single callback URL: /sso/callback.

OIDC sends a code (GET request).

SAML sends a SAMLResponse (POST request).

JWT sends an id_token (GET request).

Callback Processing:

SSOController (which listens for both GET and POST on /sso/callback) detects the protocol based on the parameters it receives.

It passes the data to the correct specialist service (OidcService, SamlService).

The service validates the token/assertion, extracts the user's email, and finds or creates the user in the users table.

A Spring Security session is established, and the user is redirected to /home.

🚀 Getting Started

Follow these steps to run the project locally.

1. Prerequisites

Java 21 (or higher)

Maven 3.x

PostgreSQL 14 (or higher)

2. Database Setup

Open psql or pgAdmin and create a new database.

CREATE DATABASE novatech_db;


The application uses spring.jpa.hibernate.ddl-auto=update, so all tables (users, sso_configurations) will be created automatically when you run the app.

3. Application Properties

Open src/main/resources/application.properties.

Ensure the PostgreSQL settings match your local database:

spring.datasource.url=jdbc:postgresql://localhost:5432/novatech_db
spring.datasource.username=<your-db-username>
spring.datasource.password=<your-db-password>


4. Create the Super Admin (CRITICAL)

The application is secured with an "untouchable" Super Admin. You must create this account manually.

Run the application once (mvn spring-boot:run).

Go to http://localhost:8080/signup and register your main admin account (e.g., your-email@company.com).

Stop the application.

Open pgAdmin and run this SQL command to promote your account. This account will now be "untouchable".

UPDATE users
SET role = 'ROLE_SUPER_ADMIN'
WHERE email = 'your-email@company.com';


5. Run and Configure

Run the application again.

mvn spring-boot:run


Log in at http://localhost:8080/login with your new Super Admin account.

You will be redirected to the Admin Dashboard (/admin/dashboard).

Navigate to one of the configuration pages (e.g., "Configure SAML").

Fill in all the required fields with the information from your Identity Provider (like miniOrange).

For SAML/JWT: You must download the X.509 certificate from your IdP, place it in the src/main/resources/ folder, and use the classpath: prefix in the form (e.g., classpath:saml_certificate.cer).

Enable the toggle and click Save.

Log out. You will now see the "Login with SAML" button on the login page.

📸 Screenshots


Admin Dashboard

SAML Configuration

Dynamic Login Page

`

`

``

License

This project is licensed under the MIT License.
