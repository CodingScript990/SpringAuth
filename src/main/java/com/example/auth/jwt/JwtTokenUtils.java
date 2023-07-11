package com.example.auth.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.time.Instant;
import java.util.Date;

@Slf4j
@Component
// JWT 관련 기능들을 넣어두기 위한 기능성 클래스
public class JwtTokenUtils {
    // JWT 는 암호화를 거쳐서 만들어지는데, 이를 위해서 암호키가 필요함
    private final Key signingKey;
    private final JwtParser jwtParser;
    // Constructor add
    public JwtTokenUtils(
            @Value("${jwt.secret}")
            String jwtSecret
    ) {
        this.signingKey
                = Keys.hmacShaKeyFor(jwtSecret.getBytes());
        // JWT 번역기 만들기
        this.jwtParser = Jwts
                .parserBuilder()
                .setSigningKey(this.signingKey)
                .build();
    }

    // 1. JWT 가 유효한지 판단하는 메서드
    // jjwt 라이브러리에서는 JWT 를 해석하는 과정에서 유효하지 않으면 예외 발생함
    public boolean validate(String token) {
        try {
            // parseClaimsJws : 암호화된 JWT 를 해석하기 위한 메서드
            // 정당하면 JWT 면 true
            jwtParser.parseClaimsJwt(token);
            return true;
        }
        // 정당하지 않는 JWT 면 false
        catch (Exception error) {
            log.warn("invalid jwt: {}", error.getClass());
            return false;
        }
    }

    // JWT 인자로 받고, 그 JWT 를 해석해서 사용자 정보를 회수하는 메서드
    public Claims parseClaims(String token) {
        return jwtParser.parseClaimsJws(token).getBody();
    }

    // 주어진 사용자 정보를 바탕으로 JWT를 문자열로 생성
    public String generateToken(UserDetails userDetails) {
        // Claims: JWT에 담기는 정보의 단위를 Claim이라 부른다.
        //         Claims는 Claim들을 담기위한 Map의 상속 interface
        Claims jwtClaims = Jwts.claims()
                // 사용자 정보 등록
                .setSubject(userDetails.getUsername())
                .setIssuedAt(Date.from(Instant.now()))
                .setExpiration(Date.from(Instant.now().plusSeconds(3600)));

        // 추가 정보를 담을수도 있음
        // jwtClaims.put("eml", ((CustomUserDetails) userDetails).getEmail());
        return Jwts.builder()
                .setClaims(jwtClaims)
                .signWith(signingKey)
                .compact();
    }
}
