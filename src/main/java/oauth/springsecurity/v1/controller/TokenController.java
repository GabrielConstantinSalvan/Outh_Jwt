package oauth.springsecurity.v1.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import oauth.springsecurity.v1.controller.dto.LoginRequest;
import oauth.springsecurity.v1.controller.dto.LoginResponse;
import oauth.springsecurity.v1.repository.UserRepository;

import java.time.Instant;
import java.util.stream.Collectors;

// Indica que esta classe é um controlador REST do Spring.
@RestController
public class TokenController {

    private final JwtEncoder jwtEncoder; // Responsável por gerar tokens JWT.
    private final UserRepository userRepository; // Repositório de usuários para buscar dados no banco.
    private BCryptPasswordEncoder passwordEncoder; // Responsável por codificar e verificar senhas.

    // Construtor para injetar as dependências.
    public TokenController(JwtEncoder jwtEncoder,
                           UserRepository userRepository,
                           BCryptPasswordEncoder passwordEncoder) {
        this.jwtEncoder = jwtEncoder;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    // Mapeia a rota POST "/login" para autenticação do usuário.
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest loginRequest) {

        // Busca o usuário no banco de dados pelo username.
        var user = userRepository.findByUsername(loginRequest.username());

        // Verifica se o usuário existe e se a senha está correta.
        if (user.isEmpty() || !user.get().isLoginCorrect(loginRequest, passwordEncoder)) {
            throw new BadCredentialsException("user or password is invalid!"); // Se inválido, lança exceção.
        }

        // Obtém o instante atual e define o tempo de expiração do token (300 segundos = 5 minutos).
        var now = Instant.now();
        var expiresIn = 300L;

        // Mapeia as roles do usuário para um formato adequado no JWT (prefixando com "ROLE_").
        var scopes = user.get().getRoles()
                .stream()
                .map(role -> "ROLE_" + role.getName()) // Exemplo: "ROLE_ADMIN"
                .collect(Collectors.joining(" ")); // Junta os roles separados por espaço.

        // Constrói as claims (informações dentro do token JWT).
        var claims = JwtClaimsSet.builder()
                .issuer("mybackend") // Define quem emitiu o token.
                .subject(user.get().getUserId().toString()) // Identifica o usuário autenticado.
                .issuedAt(now) // Define quando o token foi gerado.
                .expiresAt(now.plusSeconds(expiresIn)) // Define a expiração do token.
                .claim("scope", scopes) // Adiciona os papéis do usuário (roles) ao token.
                .build();

        // Gera o token JWT baseado nas claims definidas.
        var jwtValue = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();

        // Retorna o token gerado e o tempo de expiração na resposta.
        return ResponseEntity.ok(new LoginResponse(jwtValue, expiresIn));
    }
}
