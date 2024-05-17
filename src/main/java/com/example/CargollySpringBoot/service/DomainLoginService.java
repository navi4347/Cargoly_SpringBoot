package com.example.CargollySpringBoot.service;

import org.springframework.security.core.userdetails.UserDetails;

public interface DomainLoginService {
    boolean login(String email, String password);
    UserDetails loadUserByEmail(String email);
}
