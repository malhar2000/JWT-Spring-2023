package com.malhar.jwt.jwtauth.user;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.malhar.jwt.jwtauth.config.CUserDetailsService;
import com.malhar.jwt.jwtauth.config.JwtService;
import com.malhar.jwt.jwtauth.token.Token;
import com.malhar.jwt.jwtauth.token.TokenRepository;
import com.malhar.jwt.jwtauth.token.TokenType;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
public class AdminService {

    @Autowired
    private AdminRepository adminRepository;

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
        var user = Admin.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.ADMIN)
                .build();
        adminRepository.save(user);
    }


    public AuthenticationResponse authenticate(AuthenticationRequest request){
        userDetailsService.setRole(Role.ADMIN);
        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(auth);
        var user = adminRepository.findByUsername(request.getUsername())
                .orElseThrow();
        var jwtToken = jwtService.generateToken(Role.ADMIN.name(), auth);
        var refreshToken = jwtService.generateRefreshToken(Role.ADMIN.name(), auth);
        revokeAllUserTokens(user);
        saveUserToken(user, jwtToken);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    private void revokeAllUserTokens(Admin user) {
        var validUserTokens = tokenRepository.findAllValidTokenByAdmin(user.getId());
        if (validUserTokens.isEmpty())
            return;
        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }

    private void saveUserToken(Admin admin, String jwtToken) {
        var token = Token.builder()
                .admin(admin)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .user(null)
                .agent(null)
                .build();
        tokenRepository.save(token);
    }

    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // get the header which contains Bearer token
        final String authHeader = request.getHeader("Authorization");
        final String jwtToken;
        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            // pass the request to the next filter
            return;
        }
        // extract the token
        // 7 becoz we don;t want Bearer and the space
        jwtToken = authHeader.substring(7);

        // to do this we need a class that can manuplate jwt token
        final String username = jwtService.extractUsername(jwtToken);
        final String role = jwtService.extractClaim(jwtToken, claims -> claims.get("Role", String.class));
        // check if the user is already authenticated
        // SecurityContextHolder.getContext().getAuthentication() == null means user
        // not authenticated
        if(username != null){
            userDetailsService.setRole(Role.valueOf(role));
            UserDetails user =  userDetailsService.loadUserByUsername(username);
            Admin adminUser = adminRepository.findByUsername(username).orElseThrow();

            if(jwtService.isTokenValid(jwtToken, user)){
                 // generate new access token
                // keep refresh token same
                var accessToken = jwtService.generateToken(role, user.getUsername());
                var authResp = AuthenticationResponse.builder()
                        .accessToken(accessToken)
                        .refreshToken(jwtToken)
                        .build();
                revokeAllUserTokens(adminUser);
                saveUserToken(adminUser, accessToken);

                // how to return something in void method
                new ObjectMapper().writeValue(response.getOutputStream(), authResp);
            }
        }

    }
}
