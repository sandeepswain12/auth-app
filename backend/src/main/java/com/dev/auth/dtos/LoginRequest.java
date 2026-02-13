package com.dev.auth.dtos;

public record LoginRequest(
        String email,
        String password
) {
}