package com.example.CargollySpringBoot.model.request;


import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class DomainLoginRequest {
    @NotBlank(message = "Email is required")
    private String email;

    @NotBlank(message = "Password is required")
    private String password;
}
