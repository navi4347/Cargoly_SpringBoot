package com.example.CargollySpringBoot.controller;

import com.example.CargollySpringBoot.data.entity.DomainUser;
import com.example.CargollySpringBoot.model.request.DomainUserRequest;
import com.example.CargollySpringBoot.service.DomainUserService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api")
public class DomainUserController {
    private final DomainUserService domainUserService;

    @Autowired
    public DomainUserController(DomainUserService domainUserService) {
        this.domainUserService = domainUserService;
    }

    @GetMapping("/domainUser")
    public ResponseEntity<List<DomainUser>> getAllUsers() {
        List<DomainUser> users = domainUserService.getAllUsers();
        return ResponseEntity.ok(users);
    }

    @GetMapping("/domainUser/{id}")
    public ResponseEntity<DomainUser> getUserById(@PathVariable Long id) {
        Optional<DomainUser> userOptional = domainUserService.getUserById(id);
        return userOptional.map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/domainUser")
    public ResponseEntity<DomainUser> createUser(@Valid @RequestBody DomainUserRequest request) {
        DomainUser user = convertToEntity(request);
        user.setRole(request.getRole());
        DomainUser createdUser = domainUserService.createUser(user);
        return ResponseEntity.status(HttpStatus.CREATED).body(createdUser);
    }

    @PutMapping("/domainUser/{id}")
    public ResponseEntity<DomainUser> updateUser(@PathVariable Long id, @Valid @RequestBody DomainUserRequest request) {
        DomainUser user = convertToEntity(request);
        user.setRole(request.getRole());
        user.setEmpId(id);
        DomainUser updatedUser = domainUserService.updateUser(id, user);
        if (updatedUser != null) {
            return ResponseEntity.ok(updatedUser);
        } else {
            return ResponseEntity.notFound().build();
        }
    }



    @DeleteMapping("/domainUser/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
        domainUserService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }

    private DomainUser convertToEntity(DomainUserRequest request) {
        DomainUser user = new DomainUser();
        user.setEmpId(request.getEmpId());
        user.setName(request.getName());
        user.setEmail(request.getEmail());
        user.setPassword(request.getPassword());
        user.setContact(request.getContact());
        return user;
    }
}
