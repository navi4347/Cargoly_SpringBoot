package com.example.CargollySpringBoot.config;


import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Setter
@Getter
@Configuration
@ConfigurationProperties(prefix = "email")
public class ProviderConfiguration {
    private String host;
    private Integer port;
    private String username;
    private String email;
    private String password;
    private Boolean debug;

}
