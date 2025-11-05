package com.novatech.service_app.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * A temporary endpoint to generate a valid BCrypt hash.
     * Visit: http://localhost:8080/test/hash?password=test123
     */
    @GetMapping("/test/hash")
    public String generateHash(@RequestParam String password) {
        String hash = passwordEncoder.encode(password);

        System.out.println("--- GENERATED HASH ---");
        System.out.println(hash);
        System.out.println("----------------------");

        // Return a simple HTML page for easy copying
        return "<html><body style='font-family: monospace; font-size: 16px;'>" +
                "<h1>Password Hash Generator</h1>" +
                "<p>Password: <strong>" + password + "</strong></p>" +
                "<p>Valid BCrypt Hash:</p>" +
                "<textarea rows='3' cols='70' readonly>" + hash + "</textarea>" +
                "<p>Copy the hash above (it starts with $2a$10$) and use it in your SQL query.</p>" +
                "</body></html>";
    }
}