package com.iflytek.skillhub.compat;

import com.iflytek.skillhub.auth.token.ApiTokenAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Declares a dedicated stateless security chain for public compatibility endpoints used by
 * registry-style clients.
 */
@Configuration
public class ClawHubRegistrySecurityConfig {

    @Bean
    @Order(0)
    public SecurityFilterChain publicLabelFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher(publicLabelRequestMatcher())
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .requestCache(cache -> cache.disable())
                .securityContext(context -> context.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }

    static RequestMatcher publicLabelRequestMatcher() {
        return new OrRequestMatcher(
                new AntPathRequestMatcher("/api/v1/labels", "GET"),
                new AntPathRequestMatcher("/api/web/labels", "GET")
        );
    }

    @Bean
    @Order(1)
    public SecurityFilterChain clawHubRegistryFilterChain(
            HttpSecurity http,
            ApiTokenAuthenticationFilter apiTokenAuthenticationFilter) throws Exception {
        http
                .securityMatcher(
                        "/api/v1/search",
                        "/api/v1/download",
                        "/api/v1/skills/*"
                )
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .requestCache(cache -> cache.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(apiTokenAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
