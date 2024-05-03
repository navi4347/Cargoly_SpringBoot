package com.example.CargollySpringBoot.service.email;

import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

@Service
public class OtpService {
    private final int OTP_LENGTH = 4;
    private final Duration OTP_EXPIRATION_DURATION = Duration.ofSeconds(60);

    private Map<String, Instant> generatedEmailOtps = new HashMap<>();

    public String generateEmailOtp() {
        String otp = generateOtp(generatedEmailOtps);
        System.out.println("Generated Email OTP: " + otp);
        return otp;
    }

    public void resendEmailOtp(String email) {
        // Implementation for resending email OTP goes here
    }

    private String generateOtp(Map<String, Instant> generatedOtps) {
        Random random = new Random();
        String otp;
        do {
            otp = generateRandomOtp(random, OTP_LENGTH);
        } while (generatedOtps.containsKey(otp));

        generatedOtps.put(otp, Instant.now());
        return otp;
    }

    private String generateRandomOtp(Random random, int length) {
        StringBuilder otp = new StringBuilder();
        for (int i = 0; i < length; i++) {
            otp.append(random.nextInt(10));
        }
        return otp.toString();
    }

    public boolean validateEmailOtp(String emailOtp) {
        Instant now = Instant.now();
        Instant otpTime = generatedEmailOtps.get(emailOtp);
        if (otpTime != null && now.minus(OTP_EXPIRATION_DURATION).isBefore(otpTime)) {
            return true;
        } else {
            generatedEmailOtps.remove(emailOtp);
            return false;
        }
    }
}
