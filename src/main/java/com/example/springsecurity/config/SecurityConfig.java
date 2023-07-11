package com.example.springsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception{
        return httpSecurity
                .authorizeHttpRequests( //configurando autorizaciones
                        (request)->request
                            .requestMatchers("/v1/index2").permitAll()
                            .anyRequest().authenticated()
                )
                .formLogin( //configurando formulario de login
                        (form) -> form
                                //.loginPage("/login")
                                .successHandler(successHandler())//redirigir al hacer login
                                .permitAll()
                )
                .sessionManagement( //configurando secciones
                        (session)->session
                                .sessionFixation((sessionFixation) -> sessionFixation //manejando vulnerabilidad de fijacion de seccion
                                        .migrateSession()
                                )
                                .sessionCreationPolicy(SessionCreationPolicy.ALWAYS) //ALWAYS, IF_REQUIRED, NEVER, STATELESS
                                .invalidSessionUrl("/login")
                                .maximumSessions(1)
                                .expiredUrl("/login")
                                .sessionRegistry(sessionRegistry())
                )
                .httpBasic(// para autenticacion basica que llega por el header, util para postman
                        (basic) -> basic
                                .init(httpSecurity)
                )
                .build();
    }
    @Bean
    public SessionRegistry sessionRegistry(){
        return new SessionRegistryImpl();
    }

    public AuthenticationSuccessHandler successHandler(){
        return ((request, response, authentication) -> {
            response.sendRedirect("/v1/session");//redirigir al hacer login
        });
    }
}
