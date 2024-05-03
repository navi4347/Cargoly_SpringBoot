// DomainUserServiceImpl.java
package com.example.CargollySpringBoot.service.impl;

import com.example.CargollySpringBoot.data.entity.DomainUser;
import com.example.CargollySpringBoot.data.repo.DomainUserRepo;
import com.example.CargollySpringBoot.service.DomainUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class DomainUserServiceImpl implements DomainUserService {

    private final DomainUserRepo domainUserRepo;

    @Autowired
    public DomainUserServiceImpl(DomainUserRepo domainUserRepo) {
        this.domainUserRepo = domainUserRepo;
    }

    @Override
    public List<DomainUser> getAllUsers() {
        return domainUserRepo.findAll();
    }

    @Override
    public Optional<DomainUser> getUserById(Long id) {
        return domainUserRepo.findById(id);
    }

    @Override
    public DomainUser createUser(DomainUser user) {
        return domainUserRepo.save(user);
    }

    @Override
    public DomainUser updateUser(Long id, DomainUser user) {
        if (domainUserRepo.existsById(id)) {
            user.setEmpId(id);
            return domainUserRepo.save(user);
        }
        return null;
    }

    @Override
    public void deleteUser(Long id) {
        domainUserRepo.deleteById(id);
    }

}
