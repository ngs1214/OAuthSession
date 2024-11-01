package com.example.OAuthSession.config;

import com.example.OAuthSession.oauth2.CustomClientRegistrationRepo;
import com.example.OAuthSession.oauth2.CustomOAuth2AuthorizationService;
import com.example.OAuthSession.service.CustomOAuth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomOAuth2UserService customOAuth2UserService;
    private final CustomClientRegistrationRepo customClientRegistrationRepo;
    private final CustomOAuth2AuthorizationService customOAuth2AuthorizationService;
    private final JdbcTemplate jdbcTemplate;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .csrf((csrf) -> csrf.disable());
        http
                .formLogin((formLogin) -> formLogin.disable());
        http
                .httpBasic((httpBasic) -> httpBasic.disable());

        //custom할려면 .oauth2Client() 사용
        http
//                .oauth2Login(Customizer.withDefaults());
                .oauth2Login((oath2Login) -> oath2Login
                        .loginPage("/login")
                        //클라이언트가 OAuth2클라이언트 등록 정보를 관리
                        .clientRegistrationRepository(customClientRegistrationRepo.clientRegistrationRepository())
                        //인증된 클라이언트의 정보를 관리하며, 액세스 토큰과 리프레시 토큰 등의 정보를 저장하고 로드
                        .authorizedClientService(customOAuth2AuthorizationService.oAuth2AuthorizedClientService(jdbcTemplate,customClientRegistrationRepo.clientRegistrationRepository()))
                        .userInfoEndpoint((userInfoEndpointConfig) -> userInfoEndpointConfig
                                .userService(customOAuth2UserService)
                        )
                );
        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/", "/oauth2/**", "/login/**").permitAll()
                        .anyRequest().authenticated()
                );

        return http.build();
    }
}
