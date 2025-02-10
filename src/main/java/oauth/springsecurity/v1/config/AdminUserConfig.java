package oauth.springsecurity.v1.config;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import oauth.springsecurity.v1.entities.Role;
import oauth.springsecurity.v1.entities.User;
import oauth.springsecurity.v1.repository.RoleRepository;
import oauth.springsecurity.v1.repository.UserRepository;

import java.util.Set;

// Anotação @Configuration indica que esta classe contém configurações para o Spring.
@Configuration
public class AdminUserConfig implements CommandLineRunner { // Implementa CommandLineRunner para executar código ao iniciar a aplicação.

    private RoleRepository roleRepository; // Repositório para manipular as roles (perfis de usuário).
    private UserRepository userRepository; // Repositório para manipular os usuários.
    private BCryptPasswordEncoder passwordEncoder; // Utilizado para codificar senhas.

    // Construtor para injetar dependências.
    public AdminUserConfig(RoleRepository roleRepository,
                           UserRepository userRepository,
                           BCryptPasswordEncoder passwordEncoder) {
        this.roleRepository = roleRepository;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    @Transactional // Garante que a operação seja executada dentro de uma transação.
    //Se todas as operações forem bem-sucedidas, elas são confirmadas (commit).
    //Se alguma operação falhar, todas as operações são revertidas (rollback), garantindo a consistência dos dados.
    public void run(String... args) throws Exception {
        // Busca a role ADMIN no banco de dados.
        var roleAdmin = roleRepository.findByName(Role.Values.ADMIN.name());

        // Busca o usuário "admin" no banco de dados.
        var userAdmin = userRepository.findByUsername("admin");

        // Verifica se o usuário "admin" já existe.
        userAdmin.ifPresentOrElse(
                user -> {
                    System.out.println("admin já existe"); // Se existir, apenas exibe uma mensagem.
                },
                () -> {
                    // Se não existir, cria um novo usuário "admin".
                    var user = new User();
                    user.setUsername("admin");
                    user.setPassword(passwordEncoder.encode("123")); // Senha criptografada.
                    user.setRoles(Set.of(roleAdmin)); // Associa a role ADMIN ao usuário.
                    userRepository.save(user); // Salva o novo usuário no banco de dados.
                }
        );
    }
}
