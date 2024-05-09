package com.example.CargollySpringBoot.data.entity;


import com.example.CargollySpringBoot.service.util.AppConstants;
import jakarta.persistence.*;
import lombok.Data;



@Entity
@Data
@Table(name = AppConstants.TB_DOMAINUSER, schema = AppConstants.SCHEMA_NAME)

public class DomainUser {
    @Id
    private Long empId;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false, unique = true)
    private String email;



    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String contact;

    @Column(nullable = false)
    private String role;
}
