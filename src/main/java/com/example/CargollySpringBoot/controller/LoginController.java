package com.example.CargollySpringBoot.controller;


import com.example.CargollySpringBoot.Security.SecretKeyGenerator;
import com.example.CargollySpringBoot.model.request.LoginRequest;
import com.example.CargollySpringBoot.service.SignupService;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class LoginController {
    private final SignupService signupService;

    @Autowired
    public LoginController(SignupService signupService) {
        this.signupService = signupService;
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody LoginRequest loginRequest,
                                                     HttpServletRequest request) {
        String username = loginRequest.getUsername();
        String password = loginRequest.getPassword();

        if (signupService.authenticate(username, password)) {
            String token = generateToken(username);
            Map<String, String> response = new HashMap<>();
            response.put("token", token);
            return ResponseEntity.ok(response);
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Collections.singletonMap("error", "Invalid username or password"));
        }
    }

    @PostMapping("/csrf-token")
    public Map<String, String> getCsrfToken(HttpServletRequest request) {
        HttpSessionCsrfTokenRepository csrfTokenRepository = new HttpSessionCsrfTokenRepository();
        CsrfToken csrfToken = csrfTokenRepository.generateToken(request);
        Map<String, String> response = new HashMap<>();
        response.put("csrfToken", csrfToken.getToken());
        return response;
    }

    private String generateToken(String username) {
        String secretKey = SecretKeyGenerator.generateSecretKey();
        return Jwts.builder()
                .setSubject(username)
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();
    }

}
