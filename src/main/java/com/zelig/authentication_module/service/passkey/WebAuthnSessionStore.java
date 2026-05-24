package com.zelig.authentication_module.service.passkey;

import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class WebAuthnSessionStore {

    private static final long TTL_SECONDS = 120;

    private final Map<String, Entry<?>> sessions = new ConcurrentHashMap<>();

    public void storeRegistration(Long userId, PublicKeyCredentialCreationOptions options) {
        sessions.put(registrationKey(userId), new Entry<>(options, Instant.now().plusSeconds(TTL_SECONDS)));
    }

    public PublicKeyCredentialCreationOptions consumeRegistration(Long userId) {
        return consume(registrationKey(userId));
    }

    public String storeAssertion(AssertionRequest request) {
        String sessionId = UUID.randomUUID().toString();
        sessions.put(assertionKey(sessionId), new Entry<>(request, Instant.now().plusSeconds(TTL_SECONDS)));
        return sessionId;
    }

    public AssertionRequest consumeAssertion(String sessionId) {
        return consume(assertionKey(sessionId));
    }

    private static String registrationKey(Long userId) {
        return "reg:" + userId;
    }

    private static String assertionKey(String sessionId) {
        return "auth:" + sessionId;
    }

    @SuppressWarnings("unchecked")
    private <T> T consume(String key) {
        Entry<?> entry = sessions.remove(key);
        if (entry == null || entry.isExpired()) {
            return null;
        }
        return (T) entry.value();
    }

    private record Entry<T>(T value, Instant expiresAt) {
        boolean isExpired() {
            return Instant.now().isAfter(expiresAt);
        }
    }
}
