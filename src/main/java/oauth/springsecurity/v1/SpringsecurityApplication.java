package oauth.springsecurity.v1;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

// Anotação @SpringBootApplication que combina @Configuration, @EnableAutoConfiguration e @ComponentScan.
// Isso indica que esta é a classe principal da aplicação Spring Boot.
@SpringBootApplication
public class SpringsecurityApplication {

    // Método principal (entry point) da aplicação.
    public static void main(String[] args) {
        // Inicia a aplicação Spring Boot, carregando o contexto da aplicação.
        SpringApplication.run(SpringsecurityApplication.class, args);
    }

}
