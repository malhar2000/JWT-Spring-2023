package com.malhar.jwt.jwtauth.user;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class RegisterRequest {

    private String username;

    private String password;

    private String firstName;

    private String lastName;
}
