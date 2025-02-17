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
import oauth.springsecurity.v1.entities.Role;
import oauth.springsecurity.v1.repository.UserRepository;

import java.time.Instant;
import java.util.stream.Collectors;

// Indica que esta classe é um controlador REST do Spring.
@RestController
public class TokenController {

    // Injeta o JwtEncoder, responsável por codificar tokens JWT.
    private final JwtEncoder jwtEncoder;
    // Injeta o UserRepository, responsável por acessar os dados dos usuários no banco de dados.
    private final UserRepository userRepository;
    // Injeta o BCryptPasswordEncoder, responsável por codificar e verificar senhas.
    private BCryptPasswordEncoder passwordEncoder;

    // Construtor para injeção das dependências.
    public TokenController(JwtEncoder jwtEncoder,
                           UserRepository userRepository,
                           BCryptPasswordEncoder passwordEncoder) {
        this.jwtEncoder = jwtEncoder;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    // Endpoint para autenticação de usuários e geração de tokens JWT.
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest loginRequest) {

        // Busca o usuário no banco de dados pelo username fornecido na requisição.
        var user = userRepository.findByUsername(loginRequest.username());

        // Verifica se o usuário existe e se a senha está correta.
        // Se o usuário não existir ou a senha estiver incorreta, lança uma exceção.
        if (user.isEmpty() || !user.get().isLoginCorrect(loginRequest, passwordEncoder)) {
            throw new BadCredentialsException("user or password is invalid!");
        }

        // Obtém o momento atual para definir o tempo de emissão e expiração do token.
        var now = Instant.now();
        // Define o tempo de expiração do token em segundos (300 segundos = 5 minutos).
        var expiresIn = 300L;

        // Obtém as roles (permissões) do usuário e as converte em uma string de scopes.
        // Exemplo: Se o usuário tiver as roles "ADMIN" e "USER", o scope será "ADMIN USER".
        var scopes = user.get().getRoles()
                .stream()
                .map(Role::getName)
                .collect(Collectors.joining(" "));

        // Cria as claims (informações) que serão incluídas no token JWT.
        var claims = JwtClaimsSet.builder()
                .issuer("mybackend") // Define o emissor do token.
                .subject(user.get().getUserId().toString()) // Define o sujeito (ID do usuário).
                .issuedAt(now) // Define o momento de emissão do token.
                .expiresAt(now.plusSeconds(expiresIn)) // Define o momento de expiração do token.
                .claim("scope", scopes) // Adiciona as scopes (permissões) ao token.
                .build();

        // Codifica as claims em um token JWT.
        var jwtValue = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();

        // Retorna a resposta contendo o token JWT e o tempo de expiração.
        return ResponseEntity.ok(new LoginResponse(jwtValue, expiresIn));
    }
}