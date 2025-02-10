package oauth.springsecurity.v1.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import oauth.springsecurity.v1.entities.User;

import java.util.Optional;
import java.util.UUID;

// Define a interface UserRepository que estende JpaRepository para gerenciar a entidade User no banco de dados.
@Repository // Anotação que marca esta interface como um repositório de dados no Spring.
public interface UserRepository extends JpaRepository<User, UUID> {

    // Método personalizado para buscar um usuário pelo nome de usuário (username).
    // O Spring Data JPA irá gerar a consulta automaticamente com base na convenção do nome do método.
    Optional<User> findByUsername(String username);
}
