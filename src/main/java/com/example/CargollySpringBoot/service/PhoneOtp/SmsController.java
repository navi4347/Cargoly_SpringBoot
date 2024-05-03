package com.example.CargollySpringBoot.service.PhoneOtp;


import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import org.springframework.web.bind.annotation.*;
import com.twilio.type.PhoneNumber;

@RestController
@RequestMapping("/api")

public class SmsController {
    public static final String ACCOUNT_SID = "AC1e3bd3289447f164dab4d28c39d40340";
    public static final String AUTH_TOKEN = "b996443cfe52e4b05b3b0d44f7e4f514";

    @GetMapping(value = "/sendSMS")
    public String sendSMS() {
        Twilio.init(ACCOUNT_SID, AUTH_TOKEN);
        Message message = Message.creator(
                        new PhoneNumber("+918801607177"),
                        new PhoneNumber("+12517148580"),
                        "Test a12345678")
                .create();

        return message.getSid();
    }
}
