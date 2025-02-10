package oauth.springsecurity.v1.controller.dto;

// Define um DTO (Data Transfer Object) para a resposta de login, que inclui o token de acesso e o tempo de expiração.
public record LoginResponse(String accessToken, Long expiresIn) {
}
