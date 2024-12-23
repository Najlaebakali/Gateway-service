package com.example.gatewayservice.configuration;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class SecConfig {

    private final RsaConfig rsaConfig;

    public SecConfig(RsaConfig rsaConfig) {
        this.rsaConfig = rsaConfig;
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {

        http
                .csrf(csrf -> csrf.disable())
                .authorizeExchange(auth -> auth
                        .pathMatchers(
                                "/actuator/**",
                                "/USER-SERVICE/actuator/**",
                                "/USER-SERVICE/login",
                                "/MEDECIN-CONSULTATION-SERVICE/actuator/**",
                                "/Rendezvous-Service/actuator/**",
                                "/RENDEZVOUS-SERVICE/actuator/**").permitAll()
                        .pathMatchers("/USER-SERVICE/**").hasAuthority("SCOPE_ADMIN")
                        .pathMatchers("/RENDEZVOUS-SERVICE/**").hasAnyAuthority("SCOPE_ADMIN", "SCOPE_SECRETAIRE")
                        .pathMatchers("/MEDECIN-CONSULTATION-SERVICE/**").hasAnyAuthority("SCOPE_MEDECIN", "SCOPE_SECRETAIRE")
                        .anyExchange().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
        return http.build();
    }


    @Bean
    public ReactiveJwtDecoder jwtDecoder() {
        return NimbusReactiveJwtDecoder.withPublicKey(rsaConfig.publicKey()).build();
    }

}
