package com.malhar.jwt.jwtauth.user;

import com.malhar.jwt.jwtauth.token.Token;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

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

    @OneToMany(mappedBy = "agent")
    private List<Token> tokens;
}

