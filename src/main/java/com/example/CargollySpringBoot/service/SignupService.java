package com.example.CargollySpringBoot.service;

import com.example.CargollySpringBoot.data.entity.DomainUser;
import com.example.CargollySpringBoot.data.entity.Signup;
import com.example.CargollySpringBoot.model.request.SignupRequest;
import java.util.List;

public interface SignupService {
    Signup createSignup(SignupRequest signupRequest);

    Signup getSignupById(Long userid);

    Signup updateSignup(Long userid, SignupRequest signupRequest);

    void deleteSignup(Long userid);

    boolean authenticate(String username, String password);

    List<Signup> getAllUsers();

}
