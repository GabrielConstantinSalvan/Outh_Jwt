package oauth.springsecurity.v1.controller;

import java.util.List;
import java.util.Set;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import jakarta.transaction.Transactional;
import oauth.springsecurity.v1.controller.dto.CreateUserDto;
import oauth.springsecurity.v1.entities.Role;
import oauth.springsecurity.v1.entities.User;
import oauth.springsecurity.v1.repository.RoleRepository;
import oauth.springsecurity.v1.repository.UserRepository;

// Indica que esta classe é um controlador REST do Spring.
@RestController
public class UserController {

    private final UserRepository userRepository; // Repositório para gerenciar usuários no banco de dados.
    private final RoleRepository roleRepository; // Repositório para gerenciar roles (permissões) no banco de dados.
    private final BCryptPasswordEncoder passwordEncoder; // Codificador de senhas para armazenar senhas de forma segura.

    // Construtor para injetar as dependências.
    public UserController(UserRepository userRepository,
                          RoleRepository roleRepository,
                          BCryptPasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    // Método para criar um novo usuário. A transação garante que todas as operações sejam atômicas.
    @Transactional
    @PostMapping("/users")
    public ResponseEntity<Void> newUser(@RequestBody CreateUserDto dto) {

        // Busca o papel (role) padrão "BASIC" no banco de dados.
        var basicRole = roleRepository.findByName(Role.Values.BASIC.name());

        // Verifica se o usuário já existe no banco de dados.
        var userFromDb = userRepository.findByUsername(dto.username());

        if (userFromDb.isPresent()) {
            // Se o usuário já existir, lança uma exceção informando que a entidade não pode ser processada.
            throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY);
        }

        // Cria um novo usuário e configura suas propriedades.
        var user = new User();
        user.setUsername(dto.username()); // Define o nome de usuário.
        user.setPassword(passwordEncoder.encode(dto.password())); // Codifica a senha antes de armazená-la.
        user.setRoles(Set.of(basicRole)); // Atribui a role básica ao usuário.

        // Salva o usuário no banco de dados.
        userRepository.save(user);

        // Retorna uma resposta HTTP 200 OK sem corpo.
        return ResponseEntity.ok().build();
    }

    // Método para listar todos os usuários. Somente administradores podem acessar.
    @GetMapping("/users")
    @PreAuthorize("hasRole('admin')")
    public ResponseEntity<List<User>> listUsers() {
        var users = userRepository.findAll();
        return ResponseEntity.ok(users);
    }
}
