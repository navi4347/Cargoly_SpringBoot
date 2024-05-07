package com.example.CargollySpringBoot.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController

public class CsrfController {
    @Autowired
    private CsrfTokenRepository csrfTokenRepository;

    @GetMapping("/csrf-token")
    public Map<String, String> getCsrfToken(HttpServletRequest request) {
        CsrfToken csrfToken = csrfTokenRepository.loadToken(request);
        Map<String, String> response = new HashMap<>();

        if (csrfToken != null) {
            response.put("csrfToken", csrfToken.getToken());
        } else {
            response.put("error", "CSRF token not found");
        }

        return response;
    }
}
