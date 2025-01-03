package oauth.springsecurity.v1.controller.dto;

import java.util.List;

public record FeedDto(List<feedItemDto> feedItens, int page, int pageSize, int totalPages, long totalElements) {

}
