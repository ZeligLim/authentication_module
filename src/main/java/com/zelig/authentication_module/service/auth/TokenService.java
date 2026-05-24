package com.zelig.authentication_module.service.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;

/**
 * Signs and validates JWT access, refresh, magic-link, and MFA-pending tokens.
 */
@Service
@Slf4j
public class TokenService {

    public static final String TYPE_ACCESS = "access";
    public static final String TYPE_REFRESH = "refresh";
    public static final String TYPE_MAGIC_LINK = "magic_link";
    public static final String TYPE_MFA = "mfa";

    public static final String CLAIM_TYPE = "type";
    public static final String CLAIM_JTI = "jti";

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.expiration}")
    private long jwtExpiration;

    @Value("${jwt.refresh-expiration:604800000}")
    private long refreshExpiration;

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(jwtSecret.getBytes());
    }

    public String generateAccessToken(Long userId, String username) {
        return Jwts.builder()
                .subject(String.valueOf(userId))
                .claim("username", username)
                .claim(CLAIM_TYPE, TYPE_ACCESS)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + jwtExpiration))
                .signWith(getSigningKey())
                .compact();
    }

    public String buildRefreshTokenJwt(Long userId, String tokenId) {
        return Jwts.builder()
                .subject(String.valueOf(userId))
                .id(tokenId)
                .claim(CLAIM_TYPE, TYPE_REFRESH)
                .issuedAt(new Date())
                .expiration(Date.from(refreshTokenExpiresAt()))
                .signWith(getSigningKey())
                .compact();
    }

    public Instant refreshTokenExpiresAt() {
        return Instant.now().plusMillis(refreshExpiration);
    }

    public String generateMagicLinkToken(Long userId) {
        return Jwts.builder()
                .subject(String.valueOf(userId))
                .claim(CLAIM_TYPE, TYPE_MAGIC_LINK)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + (15 * 60 * 1000)))
                .signWith(getSigningKey())
                .compact();
    }

    public String generateMfaToken(Long userId) {
        return Jwts.builder()
                .subject(String.valueOf(userId))
                .claim(CLAIM_TYPE, TYPE_MFA)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + (5 * 60 * 1000)))
                .signWith(getSigningKey())
                .compact();
    }

    public Long extractUserId(String token) {
        return Long.valueOf(parseClaims(token).getSubject());
    }

    public String extractTokenId(String token) {
        return parseClaims(token).getId();
    }

    public String extractUsername(String token) {
        return parseClaims(token).get("username", String.class);
    }

    public String extractTokenType(String token) {
        return parseClaims(token).get(CLAIM_TYPE, String.class);
    }

    public boolean isTokenValid(String token) {
        try {
            parseClaims(token);
            return true;
        } catch (Exception e) {
            log.error("Token validation failed: {}", e.getMessage());
            return false;
        }
    }

    public boolean isTokenExpired(String token) {
        try {
            return parseClaims(token).getExpiration().before(new Date());
        } catch (Exception e) {
            return true;
        }
    }

    public boolean isTokenType(String token, String expectedType) {
        try {
            return expectedType.equals(extractTokenType(token));
        } catch (Exception e) {
            return false;
        }
    }

    private Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
