package com.example.CargollySpringBoot.service.impl;

import com.example.CargollySpringBoot.data.entity.DomainUser;
import com.example.CargollySpringBoot.data.repo.DomainUserRepo;
import com.example.CargollySpringBoot.service.DomainLoginService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service

public class DomainLoginServiceImpl  implements DomainLoginService {
    private final DomainUserRepo domainUserRepo;
    @Autowired
    public DomainLoginServiceImpl(DomainUserRepo domainUserRepo) {
        this.domainUserRepo = domainUserRepo;
    }

    @Override
    public boolean login(String email, String password) {
        DomainUser user = domainUserRepo.findByEmail(email);
        return user != null && user.getPassword().equals(password);
    }

    @Override
    public UserDetails loadUserByEmail(String email) throws UsernameNotFoundException {
        DomainUser user = domainUserRepo.findByEmail(email);
        if (user == null) {
            throw new UsernameNotFoundException("User not found with email: " + email);
        }

        return new User(
                user.getEmail(),
                user.getPassword(),
                Collections.singleton(new SimpleGrantedAuthority("ROLE_" + user.getRole()))
        );
    }
}