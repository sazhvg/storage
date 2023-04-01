package ua.in.storage.config;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.SecurityFilterChain;
import ua.in.storage.security.UserDetailsManagerImp;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

//приклад https://github.com/spring-projects/spring-security-samples/blob/main/servlet/spring-boot/java/jwt/login/src/main/java/example/RestConfig.java

@Configuration
@RequiredArgsConstructor
//@EnableWebSecurity
public class SecurityConfig {

    private static final String [] FREE_POINT_G = new String[] {
            "/api/auth/**",
            "/v2/api-docs",
            "/configuration/ui",
            "/swagger-resources/**",
            "/configuration/security",
            "/swagger-ui.html",
            "/webjars/**"};
    private static final String [] FREE_POINT_P = new String[] {
            "/api/auth/login",
            "/api/auth/refresh/token",
            "/api/auth/logout",
            "/api/auth/signup"};
    private static final String [] ADMIN_POINT_G = new String[] {
            "/api/auth/test",
            "/api/subreddit",
            "/api/subreddit/**",
            "/api/posts/**",
            "/api/posts",
            "/api/comments/**",
            "/api/comments"};
    private static final String [] ADMIN_POINT_P = new String[] {
            "/api/subreddit",
            "/api/subreddit/**",
            "/api/posts/**",
            "/api/posts",
            "/api/comments/**",
            "/api/comments"};
    private static final String [] USER_POINT_G = new String[] {
//            "/api/subreddit",
//            "/api/subreddit/**",
    };
    private static final String [] USER_POINT_P = new String[] {
//            "/api/subreddit",
//            "/api/subreddit/**",
    };
    @Value("${jwt.public.key}")
    RSAPublicKey publicKey;
    @Value("${jwt.private.key}")
    RSAPrivateKey privateKey;
    public final UserDetailsManagerImp userDetailsManagerImp;
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

//        @Bean
//        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//            // @formatter:off
//            http
//                    .authorizeHttpRequests((authorize) -> authorize
//                            .anyRequest().authenticated()
//                    )
//                    .csrf((csrf) -> csrf.ignoringRequestMatchers("/token"))
//                    .httpBasic(Customizer.withDefaults())
//                    .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
//                    .sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//                    .exceptionHandling((exceptions) -> exceptions
//                            .authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint())
//                            .accessDeniedHandler(new BearerTokenAccessDeniedHandler())
//                    );
//            // @formatter:on
//            return http.build();
//        }

//    https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/jwt.html
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity.cors().and().csrf().disable()
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(HttpMethod.GET, FREE_POINT_G).permitAll()
                        .requestMatchers(HttpMethod.POST, FREE_POINT_P).permitAll()
                        .requestMatchers(HttpMethod.GET, ADMIN_POINT_G).hasAnyAuthority("SCOPE_admin")
                        .requestMatchers(HttpMethod.POST, ADMIN_POINT_P).hasAnyAuthority("SCOPE_admin")
                        .requestMatchers(HttpMethod.GET, "/api/auth/test2").hasAnyAuthority("SCOPE_user")
                        .requestMatchers(HttpMethod.POST, "/api/auth/test2").hasAnyAuthority("SCOPE_user")
//                        .requestMatchers(HttpMethod.GET, "/api/subreddit").permitAll()
//                        .requestMatchers(HttpMethod.GET, "/api/posts/").permitAll()
//                        .requestMatchers(HttpMethod.GET, "/api/posts/**").permitAll()
//                        .requestMatchers("/v2/api-docs", "/configuration/ui", "/swagger-resources/**", "/configuration/security", "/swagger-ui.html", "/webjars/**").permitAll()
                        .anyRequest().authenticated())
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)      //      public OAuth2ResourceServerConfigurer.JwtConfigurer jwt() {
                                                                                //        if (this.jwtConfigurer == null) {
                                                                                //             this.jwtConfigurer = new OAuth2ResourceServerConfigurer.JwtConfigurer(this.context);
                                                                                //            }
                                                                                //            return this.jwtConfigurer;
                                                                                //        }
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint())
                        .accessDeniedHandler(new BearerTokenAccessDeniedHandler())
                ).build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withPublicKey(this.publicKey).build();
    }

    @Bean
    JwtEncoder jwtEncoder() {
        JWK jwk = new RSAKey.Builder(this.publicKey).privateKey(this.privateKey).build();
        JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwks);
    }

}

//    @Bean
//    DaoAuthenticationProvider daoAuthenticationProvider() {
//        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
//        provider.setPasswordEncoder(passwordEncoder());
//        provider.setUserDetailsService(userDetailsManagerImp);
//        return provider;
//    }
//


//  https://docs.spring.io/spring-authorization-server/docs/current/reference/html/getting-started.html
//
// @Configuration
//public class SecurityConfig {
//
//    @Bean
//    @Order(1)
//    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
//            throws Exception {
//        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
//        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
//                .oidc(Customizer.withDefaults());	// Enable OpenID Connect 1.0
//        http
//                // Redirect to the login page when not authenticated from the
//                // authorization endpoint
//                .exceptionHandling((exceptions) -> exceptions
//                        .authenticationEntryPoint(
//                                new LoginUrlAuthenticationEntryPoint("/login"))
//                )
//                // Accept access tokens for User Info and/or Client Registration
//                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
//
//        return http.build();
//    }
//
//    @Bean
//    @Order(2)
//    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
//            throws Exception {
//        http
//                .authorizeHttpRequests((authorize) -> authorize
//                        .anyRequest().authenticated()
//                )
//                // Form login handles the redirect to the login page from the
//                // authorization server filter chain
//                .formLogin(Customizer.withDefaults());
//
//        return http.build();
//    }
//
//    @Bean
//    public UserDetailsService userDetailsService() {
//        UserDetails userDetails = User.withDefaultPasswordEncoder()
//                .username("user")
//                .password("password")
//                .roles("USER")
//                .build();
//
//        return new InMemoryUserDetailsManager(userDetails);
//    }
//
//    @Bean
//    public RegisteredClientRepository registeredClientRepository() {
//        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
//                .clientId("messaging-client")
//                .clientSecret("{noop}secret")
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
//                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
//                .redirectUri("http://127.0.0.1:8080/authorized")
//                .scope(OidcScopes.OPENID)
//                .scope(OidcScopes.PROFILE)
//                .scope("message.read")
//                .scope("message.write")
//                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
//                .build();
//
//        return new InMemoryRegisteredClientRepository(registeredClient);
//    }
//
//    @Bean
//    public JWKSource<SecurityContext> jwkSource() {
//        KeyPair keyPair = generateRsaKey();
//        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
//        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
//        RSAKey rsaKey = new RSAKey.Builder(publicKey)
//                .privateKey(privateKey)
//                .keyID(UUID.randomUUID().toString())
//                .build();
//        JWKSet jwkSet = new JWKSet(rsaKey);
//        return new ImmutableJWKSet<>(jwkSet);
//    }
//
//    private static KeyPair generateRsaKey() {
//        KeyPair keyPair;
//        try {
//            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
//            keyPairGenerator.initialize(2048);
//            keyPair = keyPairGenerator.generateKeyPair();
//        }
//        catch (Exception ex) {
//            throw new IllegalStateException(ex);
//        }
//        return keyPair;
//    }
//
//    @Bean
//    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
//        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
//    }
//
//    @Bean
//    public AuthorizationServerSettings authorizationServerSettings() {
//        return AuthorizationServerSettings.builder().build();
//    }
//
//}
//A Spring Security filter chain for the Protocol Endpoints.
//        A Spring Security filter chain for authentication.
//        An instance of UserDetailsService for retrieving users to authenticate.
//        An instance of RegisteredClientRepository for managing clients.
//        An instance of com.nimbusds.jose.jwk.source.JWKSource for signing access tokens.
//        An instance of java.security.KeyPair with keys generated on startup used to create the JWKSource above.
//        An instance of JwtDecoder for decoding signed access tokens.
//        An instance of AuthorizationServerSettings to configure Spring Authorization Server.
