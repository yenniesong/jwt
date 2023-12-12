package com.security.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.jwt.config.auth.PrincipalDetails;
import com.security.jwt.model.JwtUser;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter가 있음
// /login 요청해서 username, password 전송하면 (post)
// UsernamePasswordAuthenticationFilter 동작을 함.
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter : 로그인 시도 중");

        // attemptAuthentication에서 id, pwd 확인 후 정상이면
        // 1. username, password 받아서
        try {
//            BufferedReader br = request.getReader();
//
//            String input = null;
//            while ((input = br.readLine()) != null) {
//                System.out.println(input);
//            }
            // 일반적으로 json으로 로그인 요청을 파싱한다면? (일반적으로 안드로이드는 json으로 요청)
            ObjectMapper om = new ObjectMapper();
            JwtUser jwtUser = om.readValue(request.getInputStream(), JwtUser.class);    // -> JwtUser 오브젝트에 담아줌

            System.out.println(jwtUser);

            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(jwtUser.getUsername(), jwtUser.getPassword());

            // PrincipalDetailsService의 loadUserByUsername() 함수가 실행된 후 정상이면 authentication이 리턴됨.
            // DB에 있는 username, password가 일치한다!
            Authentication authentication =
                    authenticationManager.authenticate(authenticationToken);
            // authentication에 토큰을 넣어 던져주면 인증을 해줌 -> authentication을 받음 -> 내 로그인한 정보를 받음

            // -> 로그인이 되었다는 뜻
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("로그인 완료 됨 : " + principalDetails.getJwtUser().getUsername());    // 로그인 정상적으로 됐다는 뜻

            System.out.println("===========================================");
            // authentication 객체가 session 영역에 저장을 해야하고 그 방법이 return 해주면 됨.
            // 굳이 리턴을 해주는 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는 것
            // 굳이 Jwt 토큰을 사용하면서 세션을 만들 이유가 없음. 근데 단지 권한 처리때문에 session에 넣어줌
            return authentication;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    // attemptAuthentication가 종료되면 실행되는 함수가 있음
    // attemptAuthentication 실행 후 인증이 정상적으로 됐으면 successfulAuthentication 함수가 실행됨.
    // JWT 토큰을 만들어서 request 요청한 사용자에게 JWT 토큰을 response 해주면 됨.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication 실행됨 => 인증이 완료되었다는 뜻!");
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        // RSA 방식은 아니고 Hash 암호 방식
        String jwtToken = JWT.create()
//                .withSubject(principalDetails.getUsername())    // 토큰 이름
                .withSubject("yeyeh 토큰")    // 토큰 이름
                .withExpiresAt(new Date(System.currentTimeMillis() + (60000*10)))    // 만료 시간 (토큰이 언제까지 유효한지)
                .withClaim("id", principalDetails.getJwtUser().getId())
                .withClaim("username", principalDetails.getJwtUser().getUsername())
                .sign(Algorithm.HMAC512("yeyeh")); // 서버만 아는 고유의 값

        response.addHeader("Authorization", "Bearer " + jwtToken);
    }
}
