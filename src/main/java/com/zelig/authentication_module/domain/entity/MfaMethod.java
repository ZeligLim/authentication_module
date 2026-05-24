package com.zelig.authentication_module.domain.entity;

import lombok.*;
import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "mfa_methods")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class MfaMethod {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private MfaType type; // TOTP, EMAIL_OTP, SMS_OTP, PASSKEY

    private String totpSecret;
    private String qrCodeUrl;

    private String emailAddress;
    private String phoneNumber;

    @Column(nullable = false)
    @Builder.Default
    private boolean isPrimary = false;

    @Column(nullable = false)
    @Builder.Default
    private boolean isVerified = false;

    private LocalDateTime verifiedAt;
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }

    public enum MfaType {
        TOTP, EMAIL_OTP, SMS_OTP, PASSKEY
    }
}