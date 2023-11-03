package com.example.security.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

/**
 * packageName    : com.example.security.config
 * fileName       : SecurityConfig
 * author         : kmy
 * date           : 11/2/23
 * description    :
 * ===========================================================
 * DATE              AUTHOR             NOTE
 * -----------------------------------------------------------
 * 11/2/23        kmy       최초 생성
 */
@Configuration
//@EnableWebSecurity
@Slf4j
public class SecurityConfig {
//public class SecurityConfig extends WebSecurityConfigurerAdapter{

//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http
//                .authorizeRequests()
//                .anyRequest().authenticated();
//        http
//                .formLogin()
////                .loginPage("/loginPage") //사용자가 인증을 해야되는 페이지
//                .defaultSuccessUrl("/")
//                .failureUrl("/login")
//                .loginProcessingUrl("/login_proc")
//                .usernameParameter("userId")
//                .passwordParameter("passwd")
//                .successHandler(new AuthenticationSuccessHandler() {
//                    @Override
//                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                        log.error("{}", authentication.getName());
//                        response.sendRedirect("/");
//                    }
//                })
//                .failureHandler(new AuthenticationFailureHandler() {
//                    @Override
//                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
//                        log.error("{}", exception.getMessage());
//                        response.sendRedirect("/login");
//                    }
//                })
//                .permitAll();
//    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http.authorizeRequests((authz)->authz.anyRequest()
                        .authenticated());
        http
                .formLogin()
//                .loginPage("/loginPage") //사용자가 인증을 해야되는 페이지
                .defaultSuccessUrl("/")
                .failureUrl("/login")
                .loginProcessingUrl("/login_proc")
                .usernameParameter("userId")
                .passwordParameter("passwd")
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        log.error("{}", authentication.getName());
                        response.sendRedirect("/");
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        log.error("{}", exception.getMessage());
                        response.sendRedirect("/login");
                    }
                })
                .permitAll()
        ;
        http.logout() //POST방식 default
                .logoutUrl("/logout") //security가 기본제공 페이지
                .logoutSuccessUrl("/login")
                .deleteCookies("JESSIONID", "remember-me")
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                        log.error("{}", "logout!!");
                        HttpSession session = request.getSession();
                        session.invalidate();
                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        log.error("{}", "logout Success!");
                    }
                });
        return http.build();
    }
}
