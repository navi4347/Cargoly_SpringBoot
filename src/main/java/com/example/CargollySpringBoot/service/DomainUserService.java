package com.example.CargollySpringBoot.service;

import com.example.CargollySpringBoot.data.entity.DomainUser;

import java.util.List;
import java.util.Optional;
import java.util.Set;

public interface DomainUserService {
    List<DomainUser> getAllUsers();

    Optional<DomainUser> getUserById(Long id);

    DomainUser createUser(DomainUser user);

    DomainUser updateUser(Long id, DomainUser user);

    void deleteUser(Long id);



}
