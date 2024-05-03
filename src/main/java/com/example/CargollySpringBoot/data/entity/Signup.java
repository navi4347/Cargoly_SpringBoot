package com.example.CargollySpringBoot.data.entity;
import com.example.CargollySpringBoot.service.util.AppConstants;
import jakarta.persistence.*;
import lombok.Data;

@Entity
@Data
@Table(name = AppConstants.TB_SIGNUP, schema = AppConstants.SCHEMA_NAME)


public class Signup {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long userid;

    @Column(nullable = false)
    private String username;

    @Column(nullable = false)
    private String password;
}
