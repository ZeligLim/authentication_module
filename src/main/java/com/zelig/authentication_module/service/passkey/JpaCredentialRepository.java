package com.zelig.authentication_module.service.passkey;

import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.PublicKeyCredentialType;
import com.zelig.authentication_module.domain.entity.PasskeyCredential;
import com.zelig.authentication_module.domain.repository.PasskeyCredentialRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

public class JpaCredentialRepository implements CredentialRepository {

    private static final Logger log = LoggerFactory.getLogger(JpaCredentialRepository.class);

    private final PasskeyCredentialRepository passkeyCredentialRepository;

    public JpaCredentialRepository(PasskeyCredentialRepository passkeyCredentialRepository) {
        this.passkeyCredentialRepository = passkeyCredentialRepository;
    }

    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
        Set<PublicKeyCredentialDescriptor> result = new HashSet<>();
        for (PasskeyCredential pc : passkeyCredentialRepository.findByUser_Username(username)) {
            String storedId = pc.getCredentialId();
            Optional<ByteArray> maybeId = parseCredentialId(storedId);
            if (maybeId.isEmpty()) {
                log.warn("Skipping malformed credentialId for user '{}': {}", username, storedId);
                continue;
            }
            result.add(PublicKeyCredentialDescriptor.builder()
                .id(maybeId.get())
                .type(PublicKeyCredentialType.PUBLIC_KEY)
                .build());
        }
        return result;
    }

    @Override
    public Optional<ByteArray> getUserHandleForUsername(String username) {
        return passkeyCredentialRepository.findByUser_Username(username).stream()
            .findFirst()
            .map(pc -> new ByteArray(
                String.valueOf(pc.getUser().getId()).getBytes(StandardCharsets.UTF_8)));
    }

    @Override
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
        try {
            String idStr = new String(userHandle.getBytes(), StandardCharsets.UTF_8);
            long userId = Long.parseLong(idStr);
            return passkeyCredentialRepository.findByUserId(userId).stream()
                .findFirst()
                .map(pc -> pc.getUser().getUsername());
        } catch (Exception e) {
            log.warn("Failed to decode userHandle to username", e);
            return Optional.empty();
        }
    }

    @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
        try {
            String cidBase64Url = credentialId.getBase64Url();

            // 1) Direct lookup by base64url string
            Optional<PasskeyCredential> opt = passkeyCredentialRepository.findByCredentialId(cidBase64Url);
            if (opt.isPresent()) {
                return buildCredential(opt.get());
            }

            // 2) Fallback: compare raw bytes across all credentials
            byte[] queryBytes = credentialId.getBytes();
            for (PasskeyCredential pc : passkeyCredentialRepository.findAll()) {
                Optional<ByteArray> storedId = parseCredentialId(pc.getCredentialId());
                if (storedId.isPresent() && Arrays.equals(storedId.get().getBytes(), queryBytes)) {
                    return buildCredential(pc);
                }
            }

            return Optional.empty();
        } catch (Exception e) {
            log.warn("lookup() failed for credentialId: {}", credentialId, e);
            return Optional.empty();
        }
    }

    @Override
    public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
        try {
            String cidBase64Url = credentialId.getBase64Url();

            // 1) Direct lookup by base64url string
            Optional<PasskeyCredential> opt = passkeyCredentialRepository.findByCredentialId(cidBase64Url);
            if (opt.isPresent()) {
                return buildCredential(opt.get())
                    .map(Collections::singleton)
                    .orElse(Collections.emptySet());
            }

            // 2) Fallback: compare raw bytes across all credentials
            Set<RegisteredCredential> result = new HashSet<>();
            byte[] queryBytes = credentialId.getBytes();
            for (PasskeyCredential pc : passkeyCredentialRepository.findAll()) {
                Optional<ByteArray> storedId = parseCredentialId(pc.getCredentialId());
                if (storedId.isPresent() && Arrays.equals(storedId.get().getBytes(), queryBytes)) {
                    buildCredential(pc).ifPresent(result::add);
                }
            }
            return result;
        } catch (Exception e) {
            log.warn("lookupAll() failed for credentialId: {}", credentialId, e);
            return Collections.emptySet();
        }
    }

    // Uses parseCredentialId instead of fromBase64Url directly — fixes the exception
    private Optional<RegisteredCredential> buildCredential(PasskeyCredential pc) {
        Optional<ByteArray> credId = parseCredentialId(pc.getCredentialId());
        if (credId.isEmpty()) {
            log.warn("Skipping unreadable credentialId for user '{}'", pc.getUser().getUsername());
            return Optional.empty();
        }
        return Optional.of(RegisteredCredential.builder()
            .credentialId(credId.get())
            .userHandle(new ByteArray(
                String.valueOf(pc.getUser().getId()).getBytes(StandardCharsets.UTF_8)))
            .publicKeyCose(new ByteArray(pc.getPublicKey()))
            .signatureCount(pc.getSignatureCounter())
            .build());
    }

    private Optional<ByteArray> parseCredentialId(String stored) {
        if (stored == null || stored.isBlank()) {
            return Optional.empty();
        }

        // 1) Try base64url (preferred)
        try {
            return Optional.of(ByteArray.fromBase64Url(stored));
        } catch (com.yubico.webauthn.data.exception.Base64UrlException e) {
            // fall through
        } catch (Exception e) {
            log.debug("Base64Url parse failed unexpectedly for credentialId: {}", stored, e);
        }

        // 2) Try standard Base64
        try {
            byte[] decoded = Base64.getDecoder().decode(stored);
            return Optional.of(new ByteArray(decoded));
        } catch (IllegalArgumentException ignored) {
        } catch (Exception e) {
            log.debug("Standard Base64 decode failed for credentialId: {}", stored, e);
        }

        // 3) Try URL-safe Base64
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(stored);
            return Optional.of(new ByteArray(decoded));
        } catch (IllegalArgumentException ignored) {
        } catch (Exception e) {
            log.debug("URL-safe Base64 decode failed for credentialId: {}", stored, e);
        }

        // 4) Try hex
        try {
            if (stored.length() % 2 == 0 && stored.matches("(?i)[0-9a-f]+")) {
                int len = stored.length();
                byte[] data = new byte[len / 2];
                for (int i = 0; i < len; i += 2) {
                    data[i / 2] = (byte) ((Character.digit(stored.charAt(i), 16) << 4)
                        + Character.digit(stored.charAt(i + 1), 16));
                }
                return Optional.of(new ByteArray(data));
            }
        } catch (Exception e) {
            log.debug("Hex decode failed for credentialId: {}", stored, e);
        }

        return Optional.empty();
    }
}