package com.security.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.security.jwt.config.auth.PrincipalDetails;
import com.security.jwt.model.JwtUser;
import com.security.jwt.repository.JwtUserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// 시큐리티가 filter를 갖고 있는데 그 필터중에 BasicAuthenticationFilter라는 것이 있음.
// 그러면 권한이나 인증이 필요한 특정 주소를 요청했을 때 이 필터를 무조건 타게 되어있음
// 만약에 권한이 아니라 인증이 필요한 주소가 아니라면 이 필터를 안탐!
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private JwtUserRepository jwtUserRepository;

    // 생성자 생성 alt + insert
    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, JwtUserRepository jwtUserRepository) {
        super(authenticationManager);
        this.jwtUserRepository = jwtUserRepository;
    }

    // 인증이나 권한이 필요한 주소 요청이 있을 때 해당 필터(doFilterInternal)를 타게 됨.
    @Override   // 내 버전에서는 doFilter가 아니라 doFilterInternal
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("인증이나 권한이 필요한 주소 요청이 됨.");

//        String jwtHeader = request.getHeader("Authorization");
        String jwtHeader = request.getHeader(JwtProperties.HEADER_STRING);

        // header가 있는지 확인
//        if (jwtHeader == null || !jwtHeader.startsWith("Bearer")){
        if (jwtHeader == null || !jwtHeader.startsWith(JwtProperties.TOKEN_PREFIX)){
            chain.doFilter(request, response);
            return;
        }
        System.out.println("jwtHeader : " + jwtHeader);

        // JWT 토큰을 검증해서 정상적인 사용자인지 확인
//        String jwtToken = request.getHeader("Authorization").replace("Bearer ", "");
        String jwtToken = request.getHeader(JwtProperties.HEADER_STRING).replace(JwtProperties.TOKEN_PREFIX, "");
        String username =
//                JWT.require(Algorithm.HMAC512("yeyeh")).build().verify(jwtToken).getClaim("username").asString();
                JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).build().verify(jwtToken).getClaim("username").asString();

        // 서명이 정상적으로 됨
        if (username != null) {
            JwtUser jwtUser = jwtUserRepository.findByUsername(username);

            // 인증은 토큰 검증시 끝. 인증을 하기 위해서가 아닌 스프링 시큐리티가 수행해주는 권한 처리를 위해
            // 아래와 같이 토큰을 만들어서 Authentication 객체를 강제로 만들고 그걸 세션에 저장!
            PrincipalDetails principalDetails = new PrincipalDetails(jwtUser);
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    principalDetails    // 나중에 컨트롤러에서 DI해서 쓸 때 사용하기 편함
                    , null  // 패스워드는 모르니까 null 처리, 어차피 지금 인증하는게 아니니까!
                    , principalDetails.getAuthorities());

            // Authentication 객체 생성, Jwt 토큰 서명을 통해서 정상이면 Authentication 객체를 만들어준다.
            // 우리가 Authentication 객체를 임의로 만들어주는 것이기 때문에 비밀번호는 null로 해줌. 우리가 이걸 만들 수 있는 근거는 username이 null이 아니기때문!
            // 그 말은 사용자가 인증이 되었다는 것 이기때문에
            // 우리가 마지막으론 권한을 알려줌. 이 객체가 실제로 로그인을 해서 만들어진 게 아니라 위에서 서명을 통해서 검증이 되서 username이 있으면 Authentication를 만들어 준다는 것
            // 정상적으로 로그인해서 만든 것은 아님

            // 강제로 시큐리티의 세션에 접근하여  값(Authentication객체를) 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        chain.doFilter(request, response);
    }
}
