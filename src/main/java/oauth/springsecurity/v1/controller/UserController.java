package oauth.springsecurity.v1.controller;

import java.util.List;
import java.util.Set;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.PathVariable;


import jakarta.transaction.Transactional;
import oauth.springsecurity.v1.controller.dto.CreateUserDto;
import oauth.springsecurity.v1.entities.Role;
import oauth.springsecurity.v1.entities.User;
import oauth.springsecurity.v1.repository.RoleRepository;
import oauth.springsecurity.v1.repository.UserRepository;

// Indica que esta classe é um controlador REST do Spring.
@RestController
public class UserController {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    // Construtor para injeção das dependências do repositório e codificador de senha.
    public UserController(UserRepository userRepository,
                          RoleRepository roleRepository,
                          BCryptPasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    // Endpoint para criação de um novo usuário.
    @Transactional // Garante que a operação de criação do usuário ocorra dentro de uma transação.
    @PostMapping("/users")
    @PreAuthorize("hasAuthority('SCOPE_admin')") // Restringe o acesso a admins
    public ResponseEntity<Void> newUser(@RequestBody CreateUserDto dto) {
        // Busca a role "BASIC" no banco de dados para atribuí-la ao novo usuário.
        var basicRole = roleRepository.findByName(Role.Values.BASIC.name());

        // Verifica se já existe um usuário com o mesmo username.
        var userFromDb = userRepository.findByUsername(dto.username());
        if (userFromDb.isPresent()) {
            // Se o usuário já existir, lança uma exceção retornando status 422 (Unprocessable Entity).
            throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY);
        }

        // Criação do novo usuário.
        var user = new User();
        user.setUsername(dto.username());
        // Codifica a senha antes de armazená-la no banco de dados.
        user.setPassword(passwordEncoder.encode(dto.password()));
        // Define a role "BASIC" para o usuário.
        user.setRoles(Set.of(basicRole));

        // Salva o novo usuário no banco de dados.
        userRepository.save(user);

        // Retorna uma resposta HTTP 200 (OK).
        return ResponseEntity.ok().build();
    }

    // Endpoint para listar todos os usuários cadastrados.
    @GetMapping("/users")
    @PreAuthorize("hasAuthority('SCOPE_admin')")
    public ResponseEntity<List<User>> listUsers() {
        var users = userRepository.findAll();
        return ResponseEntity.ok(users);
    }
    
    @DeleteMapping("/users/{username}")
    @PreAuthorize("hasAuthority('SCOPE_admin')") // Restringe o acesso a admins
    @Transactional // Garante transação
    public ResponseEntity<Void> deleteUserByUsername(@PathVariable String username) {
        // Buscar o usuário
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Usuário não encontrado: " + username));

        // Limpar as associações dos roles antes de excluir o usuário
        user.getRoles().clear(); // Remove todas as associações (se houver)

        // Deletar o usuário
        userRepository.delete(user);

        return ResponseEntity.noContent().build(); // Retorna 204 (No Content), mais adequado para DELETE
    }


}