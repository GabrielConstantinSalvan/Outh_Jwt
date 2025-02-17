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

// Anotação @Configuration indica que esta classe contém configurações do Spring.
@Configuration
public class AdminUserConfig implements CommandLineRunner {

    private RoleRepository roleRepository;
    private UserRepository userRepository;
    private BCryptPasswordEncoder passwordEncoder;

    // Construtor para injeção das dependências necessárias.
    public AdminUserConfig(RoleRepository roleRepository,
                           UserRepository userRepository,
                           BCryptPasswordEncoder passwordEncoder) {
        this.roleRepository = roleRepository;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    // Este método é executado automaticamente quando a aplicação é iniciada.
    @Override
    @Transactional // Garante que a operação de criação do usuário ocorra dentro de uma transação.
    public void run(String... args) throws Exception {

        // Busca a role "ADMIN" no banco de dados.
        var roleAdmin = roleRepository.findByName(Role.Values.ADMIN.name());

        // Verifica se já existe um usuário com o nome "admin".
        var userAdmin = userRepository.findByUsername("admin");

        userAdmin.ifPresentOrElse(
                user -> {
                    // Se o usuário já existe, imprime uma mensagem no console.
                    System.out.println("admin já existe");
                },
                () -> {
                    // Se o usuário não existe, cria um novo usuário "admin".
                    var user = new User();
                    user.setUsername("admin");
                    // Define a senha codificada utilizando BCrypt.
                    user.setPassword(passwordEncoder.encode("123"));
                    // Atribui o papel "ADMIN" ao usuário.
                    user.setRoles(Set.of(roleAdmin));
                    // Salva o novo usuário no banco de dados.
                    userRepository.save(user);
                }
        );
    }
}
