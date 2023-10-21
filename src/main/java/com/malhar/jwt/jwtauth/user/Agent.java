package com.malhar.jwt.jwtauth.user;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Entity
@Table(name = "agent")
public class Agent {

    // we create the sequence
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE)
    private Integer id;

    private String firstName;

    private String lastName;

    private String username;

    private String password;

    private boolean isActive = false;

    @Enumerated(EnumType.STRING)
    private Role role;

}

