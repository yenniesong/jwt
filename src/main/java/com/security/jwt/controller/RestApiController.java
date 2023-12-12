package com.security.jwt.controller;

import com.security.jwt.model.JwtUser;
import com.security.jwt.repository.JwtUserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RestApiController {
    @Autowired
    private JwtUserRepository jwtUserRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("home")
    public String home(){
        return "<h1> home </h1>";
    }

    @PostMapping("token")
    public String token(){
        return "<h1> token </h1>";
    }

    @PostMapping("join")
    public String join(@RequestBody JwtUser jwtUser){
        jwtUser.setPassword(bCryptPasswordEncoder.encode(jwtUser.getPassword()));
        jwtUser.setRoles("ROLE_USER"); // 롤은 기본으로 ROLE_USER 설정
        jwtUserRepository.save(jwtUser);
        return "회원가입 완.";
    }

}
