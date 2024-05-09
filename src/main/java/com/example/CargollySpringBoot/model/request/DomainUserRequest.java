package com.example.CargollySpringBoot.model.request;

import lombok.Data;

import java.util.Set;

@Data

public class DomainUserRequest {
    private Long empId;
    private String name;
    private String email;
    private String password;
    private String contact;
    private String role;
}
