package com.example.auth.controller;

import com.example.auth.dto.JwtRequestDto;
import com.example.auth.dto.JwtTokenDto;
import com.example.auth.jwt.JwtTokenUtils;
import io.jsonwebtoken.Claims;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@Slf4j
@RestController
@RequestMapping("token") // http://localhost:8080/token/** 부터 시작되는 요청들
public class TokenController {
    // UserDetailsManager: 사용자 정보 회수
    // PasswordEncoder: 비밀번호 대조용 인코더
    private final JwtTokenUtils jwtTokenUtils;
    private final UserDetailsManager manager;
    private final PasswordEncoder passwordEncoder;

    public TokenController(
            JwtTokenUtils jwtTokenUtils,
            UserDetailsManager manager,
            PasswordEncoder passwordEncoder
    ) {
        this.jwtTokenUtils = jwtTokenUtils;
        this.manager = manager;
        this.passwordEncoder = passwordEncoder;
    }

    // JWT 발급을 받는 Mapping
    // RequestBody: 인증 받고자 하는 사용자가 ID 비밀번호를 전달한다. (JwtRequestDto)
    // ResponseBody: 발급이 완료된 JWT 를 전달한다. (JwtTokenDto)

    // /token/issue: JWT 발급용 Endpoint
    @PostMapping("/issue")
    public JwtTokenDto issueJwt(
            @RequestBody JwtRequestDto dto) {
        UserDetails userDetails
                = manager.loadUserByUsername(dto.getUsername());
        // 암호화되지 않은 비밀번호와
        // 암호화된 비밀번호를 대조하여 일치하는지
        if (!passwordEncoder.matches(
                dto.getPassword(), userDetails.getPassword()
        )) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);

        JwtTokenDto response = new JwtTokenDto();
        response.setToken(jwtTokenUtils.generateToken(userDetails));
        return response;
    }

    // POST /token/secured
    // 인증이 필요한 URL
    @PostMapping("/secured")
    public String checkSecure() {
        log.info(SecurityContextHolder.getContext().getAuthentication().getName());
        return "success";
    }

    // val method
    @GetMapping("/val")
    public Claims val(@RequestParam("token") String jwt) {
        return jwtTokenUtils.parseClaims(jwt);
    }
}
