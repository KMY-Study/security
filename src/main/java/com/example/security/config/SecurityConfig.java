package com.example.security.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;

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
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {
//public class SecurityConfig extends WebSecurityConfigurerAdapter{

    private final UserDetailsService userDetailsService;

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
    public WebSecurityCustomizer webSecurityCustomizer(){
        return web -> web.ignoring().antMatchers("/actuator/**");
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http.authorizeRequests((authz)->authz.anyRequest()
                        .authenticated());

        http.formLogin()
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
                })
        ;
        http.rememberMe()
                .rememberMeParameter("remember") // remember-me default paramter name
                .tokenValiditySeconds(3600) // default 14일
                .alwaysRemember(true) // remember-me 기능이 항상 실행되도록( 비활성화때도 )
                .userDetailsService(userDetailsService) //
        ;
        // 동시세션제어
        // 최대 세션 허용 개수 초과시  1. 이전 사용자 세션 만료 정책
        //                       2. 현재 이용자 인증 실패 정책
        http.sessionManagement()
                .invalidSessionUrl("/invalid")//session이 유용하지 않을떄 이동할 페이지
                .maximumSessions(1)//최대허용 가능 세션 수 , -1:무제한세션허용
                .maxSessionsPreventsLogin(true)//동시로그인 차단 -> 인증실패 및 세션생성실패, false:기존세션만료(default)
                .expiredUrl("/expired")//세션이 만료될 경우 이동할 페이지
        ;
        // 세션고정공격보호
        http.sessionManagement()
                .sessionFixation().changeSessionId() // 기본값 default : 사용자 인증성공시 그사용자 sessions은 그대로, sessionId만 변경 servlet 3.1 이상
                                                     // none:세션아이디 세선고정공격에 노출, 공격자의 session 고정값에 의한 공격노출
                                                     // migrateSession : sevlet 3.1 이하 default
                                                     // newSession:이전세션의 속성값 사용X
        ;
        // 세션정책
        http.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                                //        SessionCreationPolicy. Always : 스프링 시큐리티가 항상 세션 생성
                                //        SessionCreationPolicy. If_Required : 스프링 시큐리티가 필요 시 생성(기본값)
                                //        SessionCreationPolicy. Never : 스프링 시큐리티가 생성하지 않지만 이미 존재하면 사용
                                //        SessionCreationPolicy. Stateless : 스프링 시큐리티가 생성하지 않고 존재해도 사용하지 않음 , (JWT로 사용할때, 설정필요)
        ;
        return http.build();
    }
}
