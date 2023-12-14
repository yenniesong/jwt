package com.security.jwt.config.jwt;

public interface JwtProperties {
    String SECRET = "yeyeh";    // 우리 서버만 알고 있는 비밀값
    int EXPIRATION_TIME = 864000000;    // 10일 (1/1000초) 60000*10 해도 상관없음
    String TOKEN_PREFIX = "Bearer ";    // 뒤에 공백
    String HEADER_STRING = "Authorization";

}
