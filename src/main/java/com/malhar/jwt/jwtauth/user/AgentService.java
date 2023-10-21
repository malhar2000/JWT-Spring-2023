package com.malhar.jwt.jwtauth.user;

import com.malhar.jwt.jwtauth.config.CUserDetailsService;
import com.malhar.jwt.jwtauth.config.JwtService;
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
    private CUserDetailsService userDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest request){
        var user = Agent.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .isActive(false)
                .role(Role.AGENT)
                .build();
        agentRepository.save(user);
        userDetailsService.setRole(Role.AGENT);
        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );
        SecurityContextHolder.getContext().setAuthentication(auth);
        var jwtToken = jwtService.generateToken(Role.AGENT.name(), auth);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
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

        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    public void activated(AgentActiveRequest activeRequest) {
        Optional<Agent> agent = agentRepository.findById(activeRequest.id);
        agent.get().setActive(true);
        agentRepository.save(agent.get());
    }
}
