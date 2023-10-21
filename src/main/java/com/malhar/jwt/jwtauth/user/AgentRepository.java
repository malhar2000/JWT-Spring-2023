package com.malhar.jwt.jwtauth.user;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AgentRepository extends JpaRepository<Agent, Integer> {
    Optional<Agent> findByUsername(String username);
}
