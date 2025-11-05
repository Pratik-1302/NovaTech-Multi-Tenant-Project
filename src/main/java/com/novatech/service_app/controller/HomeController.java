package com.novatech.service_app.controller;

import com.novatech.service_app.entity.User;
import com.novatech.service_app.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import java.security.Principal;

/**
 * HomeController:
 * - Handles home page rendering after login
 * - Displays logged-in user info
 * - Redirects root to "/home"
 */
@Controller
public class HomeController {

    @Autowired
    private UserService userService;

    /**
     * Redirect root path to home page
     */
    @GetMapping("/")
    public String rootRedirect() {
        return "redirect:/home";
    }

    /**
     * Main home page (requires authentication)
     */
    @GetMapping("/home")
    public String homePage(Model model, Principal principal) {
        if (principal != null) {
            User currentUser = userService.findByEmail(principal.getName());
            if (currentUser != null) {
                model.addAttribute("userName", currentUser.getFullName());
                model.addAttribute("userEmail", currentUser.getEmail());
                model.addAttribute("userRole", currentUser.getRole());
            } else {
                // If somehow user not found, redirect to login
                return "redirect:/login?error=true";
            }
        } else {
            // If not authenticated, redirect to login
            return "redirect:/login";
        }

        return "home"; // Renders home.html
    }
}
//working-version