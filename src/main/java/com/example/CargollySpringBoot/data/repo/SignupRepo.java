package com.example.CargollySpringBoot.data.repo;

import com.example.CargollySpringBoot.data.entity.Signup;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SignupRepo extends JpaRepository<Signup, Long> {
    boolean existsByUsername(String username);
    Signup findByUsernameAndPassword(String username, String password);

}
