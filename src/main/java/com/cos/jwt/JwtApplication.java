package com.cos.jwt;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootApplication
public class JwtApplication {

    @Bean  //IoC에 넣어주면 스프링이 알아서 비밀번호를 암호화해서 DB랑 비교 함
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    public static void main(String[] args) {
        SpringApplication.run(JwtApplication.class, args);
    }

}
