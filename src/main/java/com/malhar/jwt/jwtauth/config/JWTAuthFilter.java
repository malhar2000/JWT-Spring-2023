package com.malhar.jwt.jwtauth.config;

import com.malhar.jwt.jwtauth.user.Role;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JWTAuthFilter extends OncePerRequestFilter {


    @Autowired
    private final JwtService jwtService;
    // already exists in spring security core
    @Autowired
    private final CUserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull  FilterChain filterChain)
            throws ServletException, IOException {
        // get the header which contains Bearer token
        final String authHeader = request.getHeader("Authorization");
        final String jwtToken;
        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            // pass the request to the next filter
            filterChain.doFilter(request, response);
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
        if(username != null && SecurityContextHolder.getContext().getAuthentication() == null){
            System.out.println(role);
            userDetailsService.setRole(Role.valueOf(role));
            UserDetails user =  userDetailsService.loadUserByUsername(username);
            if(jwtService.isTokenValid(jwtToken, user)){
                // if token valid we need to
                // 1. Update security context
                // 2. send request to DispatcherServerLet

                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        user,
                        null,
                        user.getAuthorities()
                );
                // add some more details
                // It extracts information about the user's request, such as the user's IP address and the session ID.
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );

                // Update security context
                SecurityContextHolder.getContext().setAuthentication(authToken);
                System.out.println("Roles: " + authToken.getAuthorities());
            }
        }
        filterChain.doFilter(request, response);
    }
}
