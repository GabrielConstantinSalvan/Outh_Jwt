package oauth.springsecurity.v1.entities;

import jakarta.persistence.*;

// Define a entidade Role, que representa uma tabela no banco de dados para armazenar papéis (roles) de usuários.
@Entity
@Table(name = "tb_roles") // Define o nome da tabela no banco de dados onde as roles serão armazenadas.
public class Role {

    @Id // Define que o campo 'roleId' será a chave primária da tabela.
    @GeneratedValue(strategy = GenerationType.IDENTITY) // Especifica que o valor de 'roleId' será gerado automaticamente pelo banco de dados.
    @Column(name = "role_id") // Define o nome da coluna correspondente no banco de dados.
    private Long roleId; // Identificador único da role no banco de dados.
    
    private String name; // Nome da role (por exemplo, "ADMIN", "BASIC").

    // Getters e Setters:
    public Long getRoleId() {
        return roleId;
    }

    public void setRoleId(Long roleId) {
        this.roleId = roleId;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    // Enum interno para definir as roles possíveis no sistema. 
    // Ele associa um nome de role com um ID exclusivo.
    public enum Values {

        ADMIN(1L), // O papel de administrador tem o ID 1.
        BASIC(2L); // O papel básico tem o ID 2.

        long roleId;

        Values(long roleId) { // Construtor que associa cada enum a um 'roleId'.
            this.roleId = roleId;
        }

        // Método para obter o ID da role associada.
        public long getRoleId() {
            return roleId;
        }
    }
}
