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
// Habilita a segurança para requisições HTTP.
@EnableWebSecurity
// Habilita segurança baseada em anotações nos métodos (@PreAuthorize, @RolesAllowed, etc.).
@EnableMethodSecurity
public class SecurityConfig {

    // Injeta a chave pública do JWT a partir das configurações da aplicação.
    @Value("${jwt.public.key}")
    private RSAPublicKey publicKey;
    
    // Injeta a chave privada do JWT a partir das configurações da aplicação.
    @Value("${jwt.private.key}")
    private RSAPrivateKey privateKey;

    // Configura a cadeia de filtros de segurança para proteger as requisições HTTP.
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                .authorizeHttpRequests(authorize -> authorize
                        // Permite requisições POST para "/users" sem autenticação.
                        .requestMatchers(HttpMethod.POST, "/users").permitAll()
                        // Permite requisições POST para "/login" sem autenticação.
                        .requestMatchers(HttpMethod.POST, "/login").permitAll()
                        // Permite requisições POST para upload de arquivos sem autenticação.
                        .requestMatchers(HttpMethod.POST, "/api/files/upload").permitAll()
                        // Todas as outras requisições precisam estar autenticadas.
                        .anyRequest().authenticated())
                // Desabilita a proteção contra CSRF (recomendada para APIs REST).
                .csrf(csrf -> csrf.disable())
                // Configura o servidor OAuth2 para trabalhar com JWT.
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
                // Define a política de gerenciamento de sessão como STATELESS (não mantém sessões).
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build(); // Retorna a configuração de segurança construída.
    }

    // Configura um decodificador JWT para validar tokens usando a chave pública.
    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withPublicKey(publicKey).build();
    }

    // Configura um codificador JWT para gerar tokens usando a chave privada.
    @Bean
    public JwtEncoder jwtEncoder() {
        JWK jwk = new RSAKey.Builder(this.publicKey).privateKey(privateKey).build();
        var jwks = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwks);
    }

    // Configura um codificador de senhas BCrypt para armazenar senhas de forma segura.
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
