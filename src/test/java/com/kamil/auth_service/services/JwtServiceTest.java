package com.kamil.auth_service.services;


import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import java.security.SignatureException;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@TestPropertySource(properties = {
        "jwt.secret=9f648bd206e9e1b74a56df96ef928f2bacdd1c31cf0358a07cd7d7c14a94a37b8fe107b8e43b4cc24c130572c86a8f4bac028e0bb99445b28bd2042870cafa2ecea7be16c55c8c2d91409852a58de08707836d0f65ac85b440767586c8856e98d36bc4113f47bcb97dc09dc5276ffa89462165b2e321e0b6b97345b4f2c6410d84e3478b4706c8ef2c87eed2176bdb0c11125f9c7fdef654c9bfa86045e6b929def0722ee2036c1742504f8486c5bd9e5135130a7192d11be1d9111063fd43d67367a491ff71e36565c67854c5ab2dbff19bf48c1c45b5a5c5b7444e893b5625ee412a9cffa792a217bb62d8a9a089915b3359b1181b4031f447a0722af24ef6",
        "jwt.expiration=3600000" // 1 hour
})
public class JwtServiceTest {

    @Autowired
    private JwtService jwtService;

    private String email;

    @BeforeEach
    void init () {
        email = "test@o2.pl";
    }

    @Test
    void shouldGenerateValidToken() {

        String token = jwtService.generateToken(email);

        String returnedEmail = jwtService.extractUsername(token);

        assertNotNull(token);
        assertFalse(token.isEmpty());
        assertEquals(email, returnedEmail);

    }

    @Test
    void shouldReturnTrueValidTokenAndEmail() {

        String token = jwtService.generateToken(email);

        boolean isTokenValid = jwtService.isTokenValid(token, email);

        assertTrue(isTokenValid);
    }

    @Test
    void shouldReturnFalseInvalidToken() {
        String validToken = jwtService.generateToken(email);
        String invalidToken = validToken.substring(0, validToken.length() - 5) + "abcde"; // Corrupt the tokenS

        boolean isTokenValid = jwtService.isTokenValid(invalidToken, email);
        assertFalse(isTokenValid);
    }

    @Test
    void shouldReturnFalseExpiredToken() {
        String token = generateExpiredToken(email);

        boolean isTokenValid = jwtService.isTokenValid(token, email);

        assertFalse(isTokenValid);
    }

    private String generateExpiredToken(String username) {

        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis() - 3600000)) // Issued 1 hours ago
                .setExpiration(new Date(System.currentTimeMillis() - 1000)) // expired 1sec ago
                .signWith(jwtService.getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

}
