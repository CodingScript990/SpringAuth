package com.example.auth.jwt;

import com.example.auth.service.CustomUserDetails;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;

@Slf4j
@Component
// 사용자가 Header 에 포함한 JWT 를 해석하고, 그에 따라 사용자가 인증된 상태인지를 확인하는 용도임
public class JwtTokenFilter extends OncePerRequestFilter {
    private final JwtTokenUtils jwtTokenUtils;

    // Constructor
    public JwtTokenFilter(JwtTokenUtils jwtTokenUtils) {
        this.jwtTokenUtils = jwtTokenUtils;
    }

    // doFilterInternal method
    @Override
    protected void doFilterInternal(
            HttpServletRequest req,
            HttpServletResponse res,
            FilterChain filterChain
    ) throws ServletException, IOException {
        // JWT 가 포함되어 있으면 포함되어 있는 헤더를 요청
        String authHeader = req.getHeader(HttpHeaders.AUTHORIZATION);
        // authHeader 가 null 아니라면 "Bearer "로 구성되어 있어야 정상적인 인증 정보다
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            // JWT 를 회수하여 JWT 가 정상적인 JWT 인지 판단하는데,
            String token = authHeader.split(" ")[1];
            if (jwtTokenUtils.validate(token)) {
                // 웹상의 많은 예시
                // SecurityContextHolder.getContext().setAuthentication();
                // Security 공식 문서 추천!
                SecurityContext context = SecurityContextHolder.createEmptyContext();
                // JWT 에서 사용자 이름을 가져오기
                String  username = jwtTokenUtils.parseClaims(token).getSubject();

                // 일반적인 인증상태로도 사용됨
                AbstractAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                        CustomUserDetails.builder().username(username).build(),
                        token, new ArrayList<>()
                );
                // SecurityContext 에 사용자 정보 설정
                context.setAuthentication(authenticationToken);
                // SecurityContextHolder 에 SecurityContext 설정
                SecurityContextHolder.setContext(context);
                log.info("set security context with jwt");
            }
            // 아니라면 log.warn 을 통해 알림
            else log.warn("jwt validation failed");
        }
        filterChain.doFilter(req, res);
    }
}
