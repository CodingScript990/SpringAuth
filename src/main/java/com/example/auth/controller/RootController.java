package com.example.auth.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RootController {
    // http://localhost:8080/
    // 기대는 hello 이지만, security 에서 제공하는 로그인 페이지가 나옴!
    // login page[root page]
    @GetMapping
    public String root() {
        return "hello";
    }

    // http://localhost:8080/no-auth
    // no-auth 는 누구나 접근이 가능함
    @GetMapping("/no-auth")
    public String noAuth() {
        return "no auth success!";
    }

    // http://localhost:8080/re-auth
    // re-auth 는 인증된 사용자만 접근이 가능함
    @GetMapping("/re-auth")
    public String reAuth() {
        return "re auth success!";
    }
}