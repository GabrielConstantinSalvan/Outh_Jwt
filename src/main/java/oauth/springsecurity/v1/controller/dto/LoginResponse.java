package oauth.springsecurity.v1.controller.dto;

public record LoginResponse(String accessToken, Long expiresIn) {
}
