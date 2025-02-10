package oauth.springsecurity.v1.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import oauth.springsecurity.v1.entities.Role;

// Define a interface RoleRepository que estende JpaRepository para gerenciar a entidade Role no banco de dados.
@Repository // Anotação que indica que esta interface é um repositório do Spring Data JPA.
public interface RoleRepository extends JpaRepository<Role, Long> {

    // Método personalizado para buscar uma Role pelo nome..
    Role findByName(String name);
}
