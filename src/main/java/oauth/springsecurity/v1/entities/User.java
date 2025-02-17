package oauth.springsecurity.v1.entities;

import jakarta.persistence.*;
import oauth.springsecurity.v1.controller.dto.LoginRequest;

import java.util.Set;
import java.util.UUID;

import org.springframework.security.crypto.password.PasswordEncoder;

// Indica que esta classe é uma entidade JPA, ou seja, está mapeada para uma tabela no banco de dados.
@Entity
// Define o nome da tabela no banco de dados como "tb_users".
@Table(name = "tb_users")
public class User {

    // Define o ID da entidade, que será gerado automaticamente como um UUID.
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "user_id")
    private UUID userId;

    // Define uma coluna única para o username, garantindo que não haja usuários com o mesmo nome.
    @Column(unique = true)
    private String username;

    // Define a coluna para a senha do usuário.
    private String password;

    // Define um relacionamento muitos-para-muitos entre User e Role.
    // CascadeType.ALL: Todas as operações (inserir, atualizar, deletar) são propagadas para as roles.
    // FetchType.EAGER: As roles são carregadas imediatamente junto com o usuário.
    @ManyToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER)
    // Define a tabela de junção para o relacionamento muitos-para-muitos.
    @JoinTable(
            name = "tb_users_roles", // Nome da tabela de junção.
            joinColumns = @JoinColumn(name = "user_id"), // Coluna que referencia o ID do usuário.
            inverseJoinColumns = @JoinColumn(name = "role_id") // Coluna que referencia o ID da role.
    )
    private Set<Role> roles; // Conjunto de roles associadas ao usuário.

    // Método getter para o ID do usuário.
    public UUID getUserId() {
        // Exibe o ID do usuário no console (para fins de depuração).
        System.out.println("Chamando getUserId(): " + userId);
        return userId;
    }

    // Método setter para o ID do usuário.
    public void setUserId(UUID userId) {
        this.userId = userId;
    }

    // Método getter para o username.
    public String getUsername() {
        return username;
    }

    // Método setter para o username.
    public void setUsername(String username) {
        this.username = username;
    }

    // Método getter para a senha.
    public String getPassword() {
        return password;
    }

    // Método setter para a senha.
    public void setPassword(String password) {
        this.password = password;
    }

    // Método getter para as roles do usuário.
    public Set<Role> getRoles() {
        return roles;
    }

    // Método setter para as roles do usuário.
    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }

    // Método para verificar se a senha fornecida no login está correta.
    public boolean isLoginCorrect(LoginRequest loginRequest, PasswordEncoder passwordEncoder) {
        // Compara a senha fornecida no login com a senha armazenada no banco de dados.
        // Usa o PasswordEncoder para fazer a comparação de forma segura.
        return passwordEncoder.matches(loginRequest.password(), this.password);
    }
}