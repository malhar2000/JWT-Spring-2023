package com.malhar.jwt.jwtauth.user;

import com.malhar.jwt.jwtauth.config.CUserDetailsService;
import com.malhar.jwt.jwtauth.config.JwtService;
import com.malhar.jwt.jwtauth.token.Token;
import com.malhar.jwt.jwtauth.token.TokenRepository;
import com.malhar.jwt.jwtauth.token.TokenType;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AgentService {

    @Autowired
    private AgentRepository agentRepository;

    @Autowired
    private TokenRepository tokenRepository;

    @Autowired
    private CUserDetailsService userDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private AuthenticationManager authenticationManager;

    public void register(RegisterRequest request){
        var user = Agent.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .isActive(false)
                .role(Role.AGENT)
                .build();
        agentRepository.save(user);
    }


    public AuthenticationResponse authenticate(AuthenticationRequest request){
        Optional<Agent> agent = agentRepository.findByUsername(request.getUsername());
        if(agent.isPresent() && agent.get().isActive() == false){
            return null;
        }
        userDetailsService.setRole(Role.AGENT);
        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(auth);
        var user = agentRepository.findByUsername(request.getUsername())
                .orElseThrow();
        var jwtToken = jwtService.generateToken(Role.AGENT.name(), auth);
        revokeAllUserTokens(user);
        saveUserToken(user, jwtToken);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .build();
    }

    private void revokeAllUserTokens(Agent user) {
        var validUserTokens = tokenRepository.findAllValidTokenByAgent(user.getId());
        if (validUserTokens.isEmpty())
            return;
        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }

    private void saveUserToken(Agent agent, String jwtToken) {
        var token = Token.builder()
                .admin(null)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .user(null)
                .agent(agent)
                .build();
        tokenRepository.save(token);
    }


    public void activated(AgentActiveRequest activeRequest) {
        Optional<Agent> agent = agentRepository.findById(activeRequest.id);
        agent.get().setActive(true);
        agentRepository.save(agent.get());
    }

}
