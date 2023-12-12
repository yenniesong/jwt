package com.security.jwt.config.jwt;

import com.security.jwt.repository.JwtUserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private JwtUserRepository jwtUserRepository;

    // 생성자 생성 alt + insert
    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, JwtUserRepository jwtUserRepository) {
        super(authenticationManager);
        this.jwtUserRepository = jwtUserRepository;
    }

//    @Override
//    protected void doFilterIntenal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
//        throws IOException, ServletException {
//        String header = request.getHeader(JwtProperties.HEADER_STRING);
//    }
}
