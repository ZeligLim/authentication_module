package com.zelig.authentication_module.service.auth;

import com.zelig.authentication_module.api.dto.LoginResponse;
import com.zelig.authentication_module.domain.entity.RefreshToken;
import com.zelig.authentication_module.domain.entity.User;
import com.zelig.authentication_module.domain.repository.RefreshTokenRepository;
import com.zelig.authentication_module.domain.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

/**
 * Persists refresh tokens in the database with rotation and reuse detection.
 * Each login creates a token "family"; rotation revokes the previous token in that family.
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final TokenService tokenService;

    public String issue(User user, String userAgent, String ipAddress) {
        String tokenId = UUID.randomUUID().toString();
        String familyId = UUID.randomUUID().toString();
        Instant expiresAt = tokenService.refreshTokenExpiresAt();

        RefreshToken entity = RefreshToken.builder()
                .id(tokenId)
                .user(user)
                .familyId(familyId)
                .expiresAt(expiresAt)
                .createdAt(Instant.now())
                .userAgent(truncate(userAgent, 512))
                .ipAddress(truncate(ipAddress, 45))
                .build();

        refreshTokenRepository.save(entity);
        return tokenService.buildRefreshTokenJwt(user.getId(), tokenId);
    }

    public LoginResponse rotate(String refreshTokenJwt, String userAgent, String ipAddress) {
        validateRefreshJwt(refreshTokenJwt);

        String tokenId = tokenService.extractTokenId(refreshTokenJwt);
        RefreshToken current = refreshTokenRepository.findById(tokenId)
                .orElseThrow(() -> new RuntimeException("Refresh token not found"));

        if (current.isExpired()) {
            revokeTokenRecord(current);
            throw new RuntimeException("Refresh token expired");
        }

        if (current.isRevoked()) {
            revokeEntireFamily(current.getFamilyId());
            log.warn("Refresh token reuse detected for user {} family {}", current.getUser().getId(), current.getFamilyId());
            throw new RuntimeException("Refresh token has been revoked");
        }

        User user = current.getUser();
        if (!user.isActive()) {
            throw new RuntimeException("User account is disabled");
        }

        String newTokenId = UUID.randomUUID().toString();
        Instant expiresAt = tokenService.refreshTokenExpiresAt();

        current.setRevokedAt(Instant.now());
        current.setReplacedById(newTokenId);
        refreshTokenRepository.save(current);

        RefreshToken successor = RefreshToken.builder()
                .id(newTokenId)
                .user(user)
                .familyId(current.getFamilyId())
                .expiresAt(expiresAt)
                .createdAt(Instant.now())
                .userAgent(truncate(userAgent, 512))
                .ipAddress(truncate(ipAddress, 45))
                .build();
        refreshTokenRepository.save(successor);

        log.debug("Rotated refresh token {} -> {} for user {}", tokenId, newTokenId, user.getId());

        return LoginResponse.builder()
                .accessToken(tokenService.generateAccessToken(user.getId(), user.getUsername()))
                .refreshToken(tokenService.buildRefreshTokenJwt(user.getId(), newTokenId))
                .userId(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .mfaRequired(false)
                .build();
    }

    public void revoke(String refreshTokenJwt) {
        if (!tokenService.isTokenValid(refreshTokenJwt)) {
            return;
        }
        if (!tokenService.isTokenType(refreshTokenJwt, TokenService.TYPE_REFRESH)) {
            throw new RuntimeException("Invalid refresh token");
        }

        String tokenId = tokenService.extractTokenId(refreshTokenJwt);
        refreshTokenRepository.findById(tokenId).ifPresent(this::revokeTokenRecord);
    }

    public void revokeAllForUser(Long userId) {
        int revoked = refreshTokenRepository.revokeAllByUserId(userId, Instant.now());
        log.info("Revoked {} refresh token(s) for user {}", revoked, userId);
    }

    private void validateRefreshJwt(String refreshTokenJwt) {
        if (!tokenService.isTokenValid(refreshTokenJwt) || tokenService.isTokenExpired(refreshTokenJwt)) {
            throw new RuntimeException("Refresh token expired or invalid");
        }
        if (!tokenService.isTokenType(refreshTokenJwt, TokenService.TYPE_REFRESH)) {
            throw new RuntimeException("Invalid refresh token");
        }
        if (tokenService.extractTokenId(refreshTokenJwt) == null) {
            throw new RuntimeException("Invalid refresh token");
        }
    }

    private void revokeTokenRecord(RefreshToken token) {
        if (!token.isRevoked()) {
            token.setRevokedAt(Instant.now());
            refreshTokenRepository.save(token);
        }
    }

    private void revokeEntireFamily(String familyId) {
        refreshTokenRepository.revokeAllByFamilyId(familyId, Instant.now());
    }

    private static String truncate(String value, int maxLen) {
        if (value == null) {
            return null;
        }
        return value.length() <= maxLen ? value : value.substring(0, maxLen);
    }
}
