package com.example.springsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception{
        return httpSecurity
                .authorizeHttpRequests(
                        (request)->request
                            .requestMatchers("/v1/index2").permitAll()
                            .anyRequest().authenticated()
                )
                .formLogin(
                        (form) -> form
                            .loginPage("/login")
                            .permitAll()
                )
                .build();
    } // MINUTO 30
}