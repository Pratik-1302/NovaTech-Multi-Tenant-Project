package com.novatech.service_app.controller;

import com.novatech.service_app.entity.User;
import com.novatech.service_app.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class DashboardController {

    @Autowired
    private UserService userService;

    @GetMapping("/dashboard")
    public String showHomePage(Authentication authentication, Model model) {
        if (authentication != null) {
            String email = authentication.getName();
            User user = userService.findByEmail(email);

            if (user != null) {
                model.addAttribute("userName", user.getFullName());
            } else {
                model.addAttribute("userName", "User");
            }
        }
        return "dashboard"; // make sure you have  in src/main/resources/templates
    }
}
//working-version