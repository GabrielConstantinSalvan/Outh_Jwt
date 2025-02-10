package oauth.springsecurity.v1.entities;

import jakarta.persistence.*;
import oauth.springsecurity.v1.controller.dto.LoginRequest;

import java.util.Set;
import java.util.UUID;

import org.springframework.security.crypto.password.PasswordEncoder;

// Define a entidade User, que representa um usuário no sistema, com suas credenciais e roles (papéis).
@Entity
@Table(name = "tb_users") // Define o nome da tabela no banco de dados que armazena os usuários.
public class User {

    @Id // Define que o campo 'userId' será a chave primária da tabela.
    @GeneratedValue(strategy = GenerationType.UUID) // Especifica que o 'userId' será gerado como um UUID único.
    @Column(name = "user_id") // Define o nome da coluna correspondente no banco de dados.
    private UUID userId; // Identificador único do usuário, gerado automaticamente como UUID.

    @Column(unique = true) // Define que o campo 'username' deve ser único na tabela.
    private String username; // Nome de usuário único no sistema.

    private String password; // Senha do usuário (armazenada de forma segura, criptografada).

    // Relacionamento Muitos-para-Muitos com a tabela de roles (papéis) do usuário.
    @ManyToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER)
    @JoinTable(
            name = "tb_users_roles", // Nome da tabela de junção entre usuários e roles.
            joinColumns = @JoinColumn(name = "user_id"), // Define a coluna para a chave estrangeira de 'user' na tabela de junção.
            inverseJoinColumns = @JoinColumn(name = "role_id") // Define a coluna para a chave estrangeira de 'role' na tabela de junção.
    )
    private Set<Role> roles; // Conjunto de roles atribuídos ao usuário (por exemplo, "ADMIN", "BASIC").

    // Getters e Setters:
    public UUID getUserId() {
        return userId;
    }

    public void setUserId(UUID userId) {
        this.userId = userId;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }

    // Método para verificar se a senha fornecida no login corresponde à senha do usuário, após criptografada.
    public boolean isLoginCorrect(LoginRequest loginRequest, PasswordEncoder passwordEncoder) {
        // Compara a senha fornecida com a senha armazenada no banco de dados de forma criptografada.
        return passwordEncoder.matches(loginRequest.password(), this.password);
    }
}
