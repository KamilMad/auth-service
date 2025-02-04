package com.kamil.auth_service.services;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.function.Function;

@Service
public class JwtService {

    @Value("$jwt.secret")
    private String secretKey;

    @Value("${jwt.expiration}")
    private long expiration;

    // Generate a token
    public String generateToken(String username) {

        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey(), SignatureAlgorithm.ES256)
                .compact();
    }

    // Validate a token

    public boolean isTokenValid(String token, String username) {
        return (extractUsername(token).equals(username)) && !isTokenExpired(token);
    }
    // extract username
    public String extractUsername(String token) {
        return (extractClaims(token, Claims::getSubject));
    }


    //extract expiration
    private Date extractExpiration(String token) {
        return extractClaims(token, Claims::getExpiration);
    }

    // check if token is expired
    public boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // extract Claims
    private  <T> T extractClaims(String token, Function<Claims, T> clamResolver) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();

        return clamResolver.apply(claims);
    }

    // get signingKey
    private Key getSignInKey() {
        byte[] keyBytes  = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
