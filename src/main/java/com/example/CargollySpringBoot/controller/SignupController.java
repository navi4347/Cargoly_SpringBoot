package com.example.CargollySpringBoot.controller;

import com.example.CargollySpringBoot.data.entity.Signup;
import com.example.CargollySpringBoot.model.request.SignupRequest;
import com.example.CargollySpringBoot.service.SignupService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;

@RestController
@RequestMapping("/api")
public class SignupController {
    private final SignupService signupService;

    @Autowired
    public SignupController(SignupService signupService) {
        this.signupService = signupService;
    }

    @PostMapping("/signup")
    public ResponseEntity<Signup> createSignup(@RequestBody SignupRequest signupRequest) {
        Signup createdSignup = signupService.createSignup(signupRequest);
        return ResponseEntity.status(HttpStatus.CREATED).body(createdSignup);
    }

    @GetMapping("/signup/{userid}")
    public ResponseEntity<Signup> getSignupById(@PathVariable("userid") Long userid) {
        Signup signup = signupService.getSignupById(userid);
        if (signup != null) {
            return ResponseEntity.ok(signup);
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    @PutMapping("/signup/{userid}")
    public ResponseEntity<Signup> updateSignup(@PathVariable("userid") Long userid,
                                               @RequestBody SignupRequest signupRequest) {
        Signup updatedSignup = signupService.updateSignup(userid, signupRequest);
        if (updatedSignup != null) {
            return ResponseEntity.ok(updatedSignup);
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    @DeleteMapping("/signup/{userid}")
    public ResponseEntity<Void> deleteSignup(@PathVariable("userid") Long userid) {
        signupService.deleteSignup(userid);
        return ResponseEntity.noContent().build();
    }
}
