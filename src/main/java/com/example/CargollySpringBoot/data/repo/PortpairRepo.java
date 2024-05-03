package com.example.CargollySpringBoot.data.repo;

import com.example.CargollySpringBoot.data.entity.Portpair;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository

public interface PortpairRepo extends JpaRepository<Portpair, String> {
    Portpair findByPortcode(String portcode);
}
