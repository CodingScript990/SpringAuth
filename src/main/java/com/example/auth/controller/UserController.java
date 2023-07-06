package com.example.auth.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Slf4j
@Controller // 로그인 페이지를 보여줄려고함
@RequestMapping("/users")
public class UserController {
    // 어떻게 사용자를 관리하는지는 interface 기반으로 의존성 주입함
    private final UserDetailsManager manager;
    private final PasswordEncoder passwordEncoder;

    // 생성자 생성[UserDetailsManager 를 사용하기 위한 것]
    public UserController(UserDetailsManager manager, PasswordEncoder passwordEncoder) {
        this.manager = manager;
        this.passwordEncoder = passwordEncoder;
    }

    // 1. 로그인 페이지로 옴
    // 2. 로그인 페이지에 아이디 비밀번호를 입력함
    // 3. 성공하면 my-profile 로 이동함

    // login page => Get[로그인 페이지를 위한 것]
    @GetMapping("/login")
    public String loginForm() {
        return "login-form";
    }

    // login success after => Get[로그인 여부 판단]
    @GetMapping("/my-profile")
    public String myProfile(
            Authentication authentication
    ) {
        // 누가 로그인 했는지 체크할때
        log.info(authentication.getName());
        log.info(((User) authentication.getPrincipal()).getUsername());
        log.info(SecurityContextHolder.getContext().getAuthentication().getName());
        return "my-profile";
    }

    // 1. 사용자가 register page 로 온다
    // 2. 사용자가 register page 에 ID, password, password 확인을 입력
    // 3. register page 에서 /users/register 로 POST 요청
    // 4. UserDetailsManager 에 새로운 사용자 정보 추가
    @GetMapping("/register")
    public String registerForm() {
        return "register-form";
    }

    @PostMapping("/register")
    public String registerPost(
            @RequestParam("username") String username,
            @RequestParam("password") String password,
            @RequestParam("password-check") String passwordCheck
    ) {
        if (password.equals(passwordCheck)) {
            log.info("password match!");
            // username 중복도 확인해야 하지만,
            // 이 부분은 Service 에서 진행하는 것도 나쁘지 않아보임
            manager.createUser(User.withUsername(username)
                    .password(passwordEncoder.encode(password))
                    .build());
            return "redirect:/users/login";
        }
        log.warn("password does not match...");
        return "redirect:/users/register?error";
    }
}
