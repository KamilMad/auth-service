package com.kamil.auth_service.payloads;

public record LoginResponse(
        String token,
        long expiration) {
}
