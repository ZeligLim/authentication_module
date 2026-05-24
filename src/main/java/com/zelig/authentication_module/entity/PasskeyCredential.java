package com.zelig.authentication_module.entity;

import lombok.*;
import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "passkey_credentials")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PasskeyCredential {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false, unique = true)
    private String credentialId;

    @Column(nullable = false, columnDefinition = "BYTEA")
    private byte[] publicKey;

    @Column(nullable = false, columnDefinition = "BYTEA")
    private byte[] aaguid;

    private String deviceName; // e.g., "iPhone 15 Pro", "Windows Hello"

    @Column(nullable = false)
    private long signatureCounter;

    @Column(nullable = false)
    @Builder.Default
    private boolean isBackupEligible = true;

    @Column(nullable = false)
    @Builder.Default
    private boolean isBackupState = false;

    @Column(nullable = false)
    @Builder.Default
    private boolean userVerificationRequired = true;

    private LocalDateTime createdAt;
    private LocalDateTime lastUsedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }
}