package com.example.CargollySpringBoot.service.impl;


import com.example.CargollySpringBoot.data.entity.Signup;
import com.example.CargollySpringBoot.data.repo.SignupRepo;
import com.example.CargollySpringBoot.model.request.SignupRequest;
import com.example.CargollySpringBoot.service.SignupService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service

public class SignupServiceImpl implements SignupService {
    private final SignupRepo signupRepo;

    @Autowired
    public SignupServiceImpl(SignupRepo signupRepo) {
        this.signupRepo = signupRepo;
    }

    @Override
    public Signup createSignup(SignupRequest signupRequest) {
        if (signupRepo.existsByUsername(signupRequest.getUsername())) {
            return null;
        }
        Signup signup = new Signup();
        signup.setUsername(signupRequest.getUsername());
        signup.setPassword(signupRequest.getPassword());
        return signupRepo.save(signup);
    }


    @Override
    public Signup getSignupById(Long userid) {
        return signupRepo.findById(userid).orElse(null);
    }

    @Override
    public Signup updateSignup(Long userid, SignupRequest signupRequest) {
        Signup existingSignup = signupRepo.findById(userid).orElse(null);
        if (existingSignup != null) {
            existingSignup.setUsername(signupRequest.getUsername());
            existingSignup.setPassword(signupRequest.getPassword());
            return signupRepo.save(existingSignup);
        }
        return null;
    }

    @Override
    public void deleteSignup(Long userid) {
        signupRepo.deleteById(userid);
    }
    @Override
    public boolean authenticate(String username, String password) {
        Signup user = signupRepo.findByUsernameAndPassword(username, password);
        return user != null;
    }

}
