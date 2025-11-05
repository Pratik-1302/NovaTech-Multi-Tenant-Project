package com.novatech.service_app.config;

import com.novatech.service_app.service.CustomUserDetails;
import com.novatech.service_app.service.UserService;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private UserService userService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userService);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        String hierarchy = "ROLE_SUPERADMIN > ROLE_ADMIN \n ROLE_ADMIN > ROLE_USER";
        roleHierarchy.setHierarchy(hierarchy);
        return roleHierarchy;
    }

    @Bean
    public DefaultWebSecurityExpressionHandler customWebSecurityExpressionHandler() {
        DefaultWebSecurityExpressionHandler expressionHandler = new DefaultWebSecurityExpressionHandler();
        expressionHandler.setRoleHierarchy(roleHierarchy());
        return expressionHandler;
    }

    /**
     * ✅ Multi-tenant success handler (Unchanged)
     * Redirects based on user type and stores session attributes
     */
    @Bean
    public AuthenticationSuccessHandler customSuccessHandler() {
        return (request, response, authentication) -> {
            HttpSession session = request.getSession();

            // Extract custom user details
            if (authentication.getPrincipal() instanceof CustomUserDetails) {
                CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();

                // Store in session
                session.setAttribute("userType", userDetails.getUserType());
                session.setAttribute("userId", userDetails.getUserId());
                session.setAttribute("tenantId", userDetails.getTenantId());
                session.setAttribute("displayName", userDetails.getDisplayName());

                // Redirect based on user type
                String redirectUrl = switch (userDetails.getUserType()) {
                    case "SUPERADMIN" -> "/superadmin/dashboard";
                    case "TENANT_ADMIN" -> "/admin/dashboard";
                    case "END_USER" -> "/home";
                    default -> "/home";
                };

                response.sendRedirect(redirectUrl);
            } else {
                // Fallback for legacy authentication
                boolean isAdmin = authentication.getAuthorities().stream()
                        .anyMatch(auth -> auth.getAuthority().equals("ROLE_ADMIN") ||
                                auth.getAuthority().equals("ROLE_SUPERADMIN"));

                response.sendRedirect(isAdmin ? "/admin/dashboard" : "/home");
            }
        };
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf
                        .ignoringRequestMatchers("/sso/**")
                )
                .authorizeHttpRequests(auth -> auth
                        // Public pages
                        .requestMatchers(
                                "/", "/login", "/signup", "/register",
                                "/public-signup", // <-- ▼▼▼ ADDED THIS LINE ▼▼▼
                                "/sso/**", "/error",
                                "/css/**", "/js/**", "/images/**", "/test/hash" , "/favicon.ico"
                        ).permitAll()

                        // Superadmin pages
                        .requestMatchers("/superadmin/**").hasRole("SUPERADMIN")

                        // Admin pages (both superadmin and tenant-admin)
                        .requestMatchers("/admin/**").hasAnyRole("ADMIN", "SUPERADMIN")

                        // All other pages require authentication
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/login")
                        .loginProcessingUrl("/login")
                        .successHandler(customSuccessHandler())
                        .failureUrl("/login?error=true")
                        .usernameParameter("email")
                        .passwordParameter("password")
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login?logout=true")
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                        .permitAll()
                )
                .exceptionHandling(ex -> ex
                        .accessDeniedPage("/login?error=access-denied")
                );

        http.authenticationProvider(authenticationProvider());
        return http.build();
    }
}