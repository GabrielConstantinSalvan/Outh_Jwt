package oauth.springsecurity.v1.controller.dto;

// Define um DTO (Data Transfer Object) para requisição de login.
public record LoginRequest(String username, String password) {
}
