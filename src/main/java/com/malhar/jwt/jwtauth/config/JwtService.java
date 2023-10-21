package com.malhar.jwt.jwtauth.config;

import com.malhar.jwt.jwtauth.user.Role;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY = "eef42bccbf28d7bd730df181776af2063044645ee030b6df6692e15534422256";

    public String extractUsername(String token){
        // subject should be the email or the username
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsTFunction){
        final Claims claims = extractsAllClaims(token);
        return claimsTFunction.apply(claims);
    }

    // claims is the info in the token i.e. user info
    private Claims extractsAllClaims(String token){
        // signning key is a signature to verify
        // sender is who it claims to be and
        // message was not change along the way
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);

        return Keys.hmacShaKeyFor(keyBytes);
    }

    // No extraClaims
//    public String generateToken(
//            Authentication auth
//    ){
//        return generateToken(new HashMap<>(), auth);
//    }

    // extraClaims is if you want to pass other details like authority of etc..
    public String generateToken(
            String role,
            Authentication auth
            ){
        String username = auth.getName();
        // token valid for 24 hours
        // compact will generate and return the token
        return Jwts
                .builder()
                .claim("Role", Role.valueOf(role).name())
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // check if token is valid
    public boolean isTokenValid(String token, UserDetails userDetails){
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    // check if it is before
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // get expiration date
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }


}
