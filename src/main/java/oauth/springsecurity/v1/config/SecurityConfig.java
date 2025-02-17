package oauth.springsecurity.v1.config;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.SecurityFilterChain;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

// Indica que esta classe é uma configuração do Spring.
@Configuration
@EnableWebSecurity // Habilita a configuração de segurança da web do Spring Security.
@EnableMethodSecurity // Permite a segurança baseada em anotações nos métodos.
public class SecurityConfig {

    // Injeção das chaves RSA do JWT a partir das propriedades do aplicativo.
    @Value("${jwt.public.key}")
    private RSAPublicKey publicKey;
    
    @Value("${jwt.private.key}")
    private RSAPrivateKey privateKey;

    // Configuração da segurança HTTP
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                .authorizeHttpRequests(authorize -> authorize
                        // Permite acesso sem autenticação às rotas de criação de usuário e login.
                        .requestMatchers(HttpMethod.POST, "/users").permitAll()
                        .requestMatchers(HttpMethod.POST, "/login").permitAll()
                        // Exige autenticação para todas as outras requisições.
                        .anyRequest().authenticated())
                // Desativa a proteção contra CSRF (Cross-Site Request Forgery),
                // pois a aplicação é stateless e usa tokens.
                .csrf(csrf -> csrf.disable())
                // Configura o servidor de recursos OAuth2 para usar JWT.
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
                // Define a política de gerenciamento de sessões como STATELESS
                // (sem estado), garantindo que a autenticação seja feita via token JWT.
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }

    // Bean responsável por decodificar tokens JWT utilizando a chave pública RSA.
    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withPublicKey(publicKey).build();
    }

    // Bean responsável por codificar tokens JWT utilizando as chaves RSA.
    @Bean
    public JwtEncoder jwtEncoder() {
        JWK jwk = new RSAKey.Builder(this.publicKey).privateKey(privateKey).build();
        var jwks = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwks);
    }

    // Bean para codificação de senhas usando BCrypt.
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
