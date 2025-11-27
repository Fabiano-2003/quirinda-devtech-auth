package com.quirinda.auth.dto;

public final class AuthResponse {
    private final String token;
    private final String username;
    private final String message;

    public AuthResponse(String token, String username, String message) {
        this.token = token;
        this.username = username;
        this.message = message;
    }

    public String getToken() {
        return token;
    }

    public String getUsername() {
        return username;
    }

    public String getMessage() {
        return message;
    }
}
