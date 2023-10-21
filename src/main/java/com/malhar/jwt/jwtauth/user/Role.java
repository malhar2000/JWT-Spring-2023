package com.malhar.jwt.jwtauth.user;

public enum Role {
    ADMIN("Admin"),
    USER("User"),
    AGENT("Agent");

    private final String role;

    Role(String role) {
        this.role = role;
    }

    @Override
    public String toString() {
        return role;
    }
}
