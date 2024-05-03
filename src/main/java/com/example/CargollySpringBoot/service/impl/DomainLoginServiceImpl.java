package com.example.CargollySpringBoot.service.impl;

import com.example.CargollySpringBoot.data.entity.DomainUser;
import com.example.CargollySpringBoot.data.repo.DomainUserRepo;
import com.example.CargollySpringBoot.service.DomainLoginService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

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
}
