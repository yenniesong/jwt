package com.security.jwt.config;

import com.security.jwt.config.jwt.JwtAuthenticationFilter;
import com.security.jwt.config.jwt.JwtAuthorizationFilter;
import com.security.jwt.repository.JwtUserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Autowired
    private JwtUserRepository jwtUserRepository;

    @Autowired
    private CorsConfig corsConfig;
    @Bean
    protected SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http.csrf().disable()
                // session을 만드는 방식도 안씀
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .formLogin().disable()  // form 태그를 안사용한다!
                .httpBasic().disable()  // 기본적인 http 방식도 안사용한다!
                .apply(new MyCustomDsl())   // 커스텀 필터 등록
                .and()
                .authorizeRequests(authroize -> authroize.antMatchers("/api/v1/user/**")
                    .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                    .antMatchers("/api/v1/manager/**")
                    .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                    .antMatchers("/api/v1/admin/**")
                    .access("hasRole('ROLE_ADMIN')")
                    .anyRequest().permitAll())
                .build();
    }

    public class MyCustomDsl extends AbstractHttpConfigurer<MyCustomDsl, HttpSecurity> {
        @Override
        public void configure(HttpSecurity http) throws Exception {
            AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
            http
                    .addFilter(corsConfig.corsFilter())
                    .addFilter(new JwtAuthenticationFilter(authenticationManager))
                    .addFilter(new JwtAuthorizationFilter(authenticationManager, jwtUserRepository));
        }
    }



}
