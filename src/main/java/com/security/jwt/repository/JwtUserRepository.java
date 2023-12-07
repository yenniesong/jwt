package com.security.jwt.repository;

import com.security.jwt.model.JwtUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface JwtUserRepository extends JpaRepository<JwtUser, Long> {
    // findBy 규칙 -> Username 문법
    // select * from user where username=1?
    public JwtUser findByUsername(String username);
}
