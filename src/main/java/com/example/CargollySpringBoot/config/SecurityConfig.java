
package com.example.CargollySpringBoot.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import static org.springframework.security.config.Customizer.withDefaults;


@Configuration
@EnableWebSecurity

public class SecurityConfig  {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(csrf -> csrf.disable())
                .authorizeRequests(authorizeRequests -> authorizeRequests
                        .requestMatchers("/swagger-ui/**", "/swagger-ui.html", "/v3/api-docs/**").permitAll()
                        .requestMatchers("/api/userLogin").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/domainLogin", "/api/validateOtp", "/api/resendOtp").permitAll()
                        .requestMatchers("/api/portpair").permitAll()
                        .requestMatchers( HttpMethod.POST, "/api/signup").permitAll()
                        .requestMatchers(HttpMethod.GET,  "/api/signup").hasRole("SuperAdmin")
                        .requestMatchers(HttpMethod.PUT,  "/api/signup").hasRole("SuperAdmin")
                        .requestMatchers(HttpMethod.DELETE,  "/api/signup").hasRole("SuperAdmin")
                        .requestMatchers( HttpMethod.POST, "/api/domainUser").permitAll()
                        .requestMatchers(HttpMethod.GET,  "/api/domainUser").hasRole("SuperAdmin")
                        .requestMatchers(HttpMethod.PUT,  "/api/domainUser").hasRole("SuperAdmin")
                        .requestMatchers(HttpMethod.DELETE,  "/api/domainUser").hasRole("SuperAdmin")
                        .requestMatchers("/menu").hasRole("Employee")


                        .anyRequest().authenticated()
                )
                .formLogin(withDefaults())
                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean

    public InMemoryUserDetailsManager userDetailsManager(PasswordEncoder encoder) {
        UserDetails superAdmin = User.withUsername("superAdmin")
                .password(encoder.encode("!@#$%^&*"))
                .roles("SuperAdmin")
                .build();
        UserDetails admin = User.withUsername("admin")
                .password(encoder.encode("cargoly"))
                .roles("ADMIN")
                .build();
        UserDetails Employee = User.withUsername("employee")
                .password(encoder.encode("123456"))
                .roles("Employee")
                .build();
        UserDetails Users = User.withUsername("Users")
                .password(encoder.encode("password"))
                .roles("Users")
                .build();

        return new InMemoryUserDetailsManager(superAdmin, admin, Employee, Users);
    }

}