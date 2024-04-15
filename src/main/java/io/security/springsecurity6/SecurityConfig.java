package io.security.springsecurity6;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;

@EnableWebSecurity
@Configuration
public class SecurityConfig  {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {

        httpSecurity
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/anonymous").hasRole("GUEST")
                        .requestMatchers("/authenticationContext", "/authentication").permitAll()
                        .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
                .rememberMe(rememberMe -> rememberMe
                        //.alwaysRemember(true)
                        .tokenValiditySeconds(3600)
                        .userDetailsService(userDetailsService())
                        .rememberMeParameter("remember")
                        .rememberMeCookieName("remember")
                        .key("security")
                )
                .anonymous(anonymous -> anonymous
                        .principal("guest")
                        .authorities("ROLE_GUEST")
                )
        ;

//         httpSecurity
//                 .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
//                 .formLogin(form -> form
////                         .loginPage("/loginPage")
//                         .loginProcessingUrl("/loginProc")
//                         .defaultSuccessUrl("/", false)
//                         .failureUrl("/failed")
//                         .usernameParameter("userId")
//                         .passwordParameter("passwd")
//                         .successHandler((request, response, authentication) -> {
//                             System.out.println("authentication: " + authentication);
//                             response.sendRedirect("/home");
//                         })
//                         .failureHandler((request, response, exception) -> {
//                             System.out.println("exception: " + exception.getMessage());
//                             response.sendRedirect("/login");
//                         })
//                         .permitAll()
//                 );

         return  httpSecurity.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("user")
                .password("{noop}1111")
                .roles(" USER").build();
        return new InMemoryUserDetailsManager(user);
    }
}
