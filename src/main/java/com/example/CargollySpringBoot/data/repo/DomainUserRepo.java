package com.example.CargollySpringBoot.data.repo;


import com.example.CargollySpringBoot.data.entity.DomainUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository

public interface DomainUserRepo extends JpaRepository<DomainUser, Long> {
    DomainUser findByEmail(String email);

}
