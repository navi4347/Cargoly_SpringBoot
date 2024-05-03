package com.example.CargollySpringBoot.controller;

import com.example.CargollySpringBoot.Security.SecretKeyGenerator;
import com.example.CargollySpringBoot.model.request.DomainLoginRequest;
import com.example.CargollySpringBoot.service.DomainLoginService;
import com.example.CargollySpringBoot.service.email.OtpService;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@Component
@RestController
@RequestMapping("/api")
public class DomainLoginController {
    private static final Logger logger = LoggerFactory.getLogger(DomainLoginController.class);

    private final DomainLoginService domainLoginService;
    private final OtpService otpService;
    private final JavaMailSender mailSender;

    @Autowired
    public DomainLoginController(DomainLoginService domainLoginService, OtpService otpService, JavaMailSender mailSender) {
        this.domainLoginService = domainLoginService;
        this.otpService = otpService;
        this.mailSender = mailSender;
    }

    @PostMapping("/domainLogin")
    public ResponseEntity<Object> login(@Valid @RequestBody DomainLoginRequest loginRequest) {
        boolean loginSuccess = domainLoginService.login(loginRequest.getEmail(), loginRequest.getPassword());
        if (loginSuccess) {
            String emailOtp = otpService.generateEmailOtp();
            String token = generateToken(loginRequest.getEmail());

            Map<String, Object> responseBody = new HashMap<>();
            responseBody.put("token", token);
            responseBody.put("emailOtp", emailOtp);

            try {
                sendEmail(loginRequest.getEmail(), "Email Verification", "Use the following OTP to complete your Login procedures, OTP valid for 60sec", emailOtp);
                logger.info("Email sent successfully to {}", loginRequest.getEmail());
            } catch (Exception e) {
                logger.error("Error sending email: {}", e.getMessage());
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error sending email");
            }

            return ResponseEntity.ok(responseBody);
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid email or password");
        }
    }

    @PostMapping("/validateOtp")
    public ResponseEntity<Object> validateOtp(@RequestBody Map<String, String> otpData) {
        String emailOtp = otpData.get("emailOtp");
        boolean isValid = otpService.validateEmailOtp(emailOtp);
        if (isValid) {
            return ResponseEntity.ok().body(Map.of("isValid", true));
        } else {
            return ResponseEntity.ok().body(Map.of("isValid", false));
        }
    }

    @PostMapping("/resendOtp")
    public ResponseEntity<Object> resendOtp(@RequestBody Map<String, String> requestData) {
        String email = requestData.get("email");
        String emailOtp = otpService.generateEmailOtp();
        otpService.resendEmailOtp(email);
        try {
            sendEmail(email, "Your subject", "Your message", emailOtp);
            logger.info("Email resent successfully to {}", email);
        } catch (Exception e) {
            logger.error("Error resending email: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error resending email");
        }
        return ResponseEntity.ok().build();
    }

    private String generateToken(String email) {
        String secretKey = SecretKeyGenerator.generateSecretKey();
        return Jwts.builder()
                .setSubject(email)
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();
    }

    private void sendEmail(String to, String subject, String text, String emailOtp) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject(subject);
        message.setText(text + "\n\nYour Email OTP is: " + emailOtp);

        mailSender.send(message);
    }

}
