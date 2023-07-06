package com.example.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

// 버전 이전 : extends WebSecurityConfigurerAdapter
// 버전 이후 : Builder -> Lambda 를 이용 DSL 기반 설정
@Configuration
// @EnableWebSecurity : 2.1버전 이후 SpringBoot Starter Security 에서는 필수 아님
public class WebSecurityConfig {
    // 설정으로 등록 작업
    // @Bean : 메서드의 결과를 BEAN 객체로 등록해주는 어노테이션을 말함
    @Bean // 설명 : return 을 해주는 결과가 빈 어노테이션에게 부여하여 spring container 에 의해 관리를 해준다는 의미임
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http // DI 자동으로 설정됨, 빌더 패턴 처럼 쓴다는 의미
    ) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                // 1. requestMatchers를 통해 설정할 URL 지정
                // 2. permitAll(), authenticated() 등을 통해 어떤 사용자가
                //    접근 가능한지 설정
                .authorizeHttpRequests(
                        authHttp -> authHttp // HTTP 요청 허가 관련 설정을 하고 싶다.
                                // requestMatchers == 어떤 URL로 오는 요청에 대하여 설정하는지
                                // permitAll() == 누가 요청해도 허가한다.
                                .requestMatchers("/no-auth")
                                .permitAll()
                                .requestMatchers(
                                        "/re-auth",
                                        "/users/my-profile"
                                )
                                .authenticated()  // 인증이 된 사용자만 허가
                                .requestMatchers("/", "/users/register")
                                .anonymous()  // 인증이 되지 않은 사용자만 허가
                )
                // form 을 이용한 로그인 관련 설정
                .formLogin(
                        formLogin -> formLogin
                                // 로그인 하는 페이지(경로)를 지정 => login
                                .loginPage("/users/login")
                                // 로그인 성공시 이동하는 페이지(경로) => my-profile
                                .defaultSuccessUrl("/users/my-profile")
                                // 로그인 실패시 이동하는 페이지(경로) => fail
                                .failureUrl("/users/login?fail")
                                // 로그인 과정에서 필요한 경로들을
                                // 모든 사용자가 사용할 수 있게끔 권한설정
                                .permitAll()
                )
                // 로그아웃 관련 설정
                // 로그인 -> 쿠키를 통해 세션을 생성
                //   필수 : (아이디와 비밀번호)
                // 로그아웃 -> 세션을 제거
                //         -> 세션정보만 있으면 제거 가능함
                .logout(logout -> logout
                        // 로그아웃 요청을 보낼 URL
                        // 어떤 UI에 로그아웃 기능을 연결하고 싶으면 해당 UI가 /users/logout 으로 POST 요청을 보내게끔
                        .logoutUrl("/users/logout")
                        // 로그아웃 성공시 이동할 URL 설정 => login
                        .logoutSuccessUrl("/users/login")
                );
        // 401 => 인증되지 않음 ,403 => 누군지는 알지만 허가되지 않음
        return http.build();
    }

    @Bean
    // 사용자 관리를 위한 Interface 구현체 Bean
    public UserDetailsManager userDetailsManager(
            PasswordEncoder passwordEncoder // Password 인증을 활용하기 위한 작업
    ) {
        // 임시 User
        UserDetails user1 = User.withUsername("test")
                .password(passwordEncoder.encode("test1234"))
                .build();
        // Spring 에서 미리 만들어놓은 사용자 인증 서비스
        return new InMemoryUserDetailsManager(user1); // 메모리 해쉬맵을 통해서 인증서비스를 관리하는 것[구현체]
    }

    @Bean
    // 비밀번호 암호화를 위한 Bean
    public PasswordEncoder passwordEncoder() {
        // 기본적으로 사용자 비밀번호는 해독가능한 형태로 DB 에 Save 되면 안됨!
        // 기본적으로 암호화 하거나 단방향 암호화 하는 인코더를 사용함
        return new BCryptPasswordEncoder();
    }
}
