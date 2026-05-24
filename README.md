# Authentication Module

Spring Boot service that provides sign-in, multi-factor authentication (MFA), passkeys (WebAuthn), and OAuth2 social login. Clients receive JWT access tokens and rotating refresh tokens.

## Requirements

- Java 25
- Maven 3.9+
- PostgreSQL (production) or H2 (dev profile)

## Quick start

```bash
./mvnw spring-boot:run
```

Default profile is `dev` (in-memory H2, SMS OTP logged to console). API base URL: `http://localhost:8080`.

## Project layout

```
src/main/java/com/zelig/authentication_module/
├── AuthenticationModuleApplication.java   # Entry point
├── api/                                   # HTTP layer
│   ├── controller/
│   │   ├── SessionController.java         # Login, register, refresh, logout, magic link
│   │   ├── MfaController.java             # TOTP / email / SMS MFA
│   │   └── PasskeyController.java         # WebAuthn passkeys
│   ├── dto/                               # Request/response JSON models
│   ├── exception/                         # Global error handling
│   └── util/                              # RequestUtils (IP, user-agent)
├── config/                                # Spring Security, WebAuthn beans
├── domain/                                # Persistence
│   ├── entity/                            # User, RefreshToken, MfaMethod, …
│   └── repository/                        # Spring Data JPA
├── security/                              # JWT filter, OAuth2 success handler
└── service/                               # Business logic
    ├── auth/                              # Tokens, sessions, email magic link
    ├── oauth/                             # Google / Facebook / Apple linking
    ├── mfa/                               # MFA orchestration
    │   └── otp/                           # Email/SMS delivery, OTP storage
    └── passkey/                           # WebAuthn + challenge session store
```

### Layer responsibilities

| Layer | Role |
|-------|------|
| **api** | REST endpoints only; no business rules |
| **service** | All authentication logic |
| **domain** | Database entities and repositories |
| **security** | JWT parsing, OAuth2 callback |
| **config** | Bean wiring for Security and WebAuthn |

## Authentication flows

### 1. Password login

```
POST /api/auth/login  →  { accessToken, refreshToken }  OR  { mfaRequired, mfaToken, mfaMethod }
```

If MFA is enabled, complete with `POST /api/auth/mfa/verify` (see below).

### 2. Refresh token rotation

Every refresh invalidates the previous refresh token and returns a new pair:

```
POST /api/auth/refresh  { "refreshToken": "..." }
```

Store the **latest** refresh token after each call. Reusing an old token revokes the entire token family (possible theft).

### 3. Logout

```
POST /api/auth/logout       { "refreshToken": "..." }     # one device
POST /api/auth/logout/all   Authorization: Bearer …     # all devices
```

### 4. Magic link email

```
POST /api/auth/login/email   { "email": "user@example.com" }
GET  /api/auth/magic-link?token=...
```

### 5. MFA

**Enrollment** (requires access token):

| Method | Enroll | Confirm |
|--------|--------|---------|
| TOTP | `POST /api/auth/mfa/totp/enroll` | `POST /api/auth/mfa/totp/confirm?code=123456` |
| Email OTP | `POST /api/auth/mfa/email/enroll` | `POST /api/auth/mfa/email/confirm?code=123456` |
| SMS OTP | `POST /api/auth/mfa/sms/enroll` | `POST /api/auth/mfa/sms/confirm?code=123456` |

**Login** (after primary auth returns `mfaToken`):

```
POST /api/auth/mfa/verify      { "mfaToken", "code" }
POST /api/auth/mfa/otp/resend  { "mfaToken" }          # email/SMS only
```

### 6. Passkeys (WebAuthn)

**Register** (authenticated):

```
POST /api/auth/passkey/register/start
POST /api/auth/passkey/register/finish   { "credentialJson", "deviceName" }
```

**Sign in** (public):

```
POST /api/auth/passkey/authenticate/start   →  { sessionId, options }
POST /api/auth/passkey/authenticate/finish  { "sessionId", "credentialJson" }
```

`credentialJson` is the full `PublicKeyCredential` object from `navigator.credentials.create()` / `get()`.

### 7. OAuth2 social login

Browser flow: `/oauth2/authorization/google` (or `facebook`, `apple`).  
On success, JSON `LoginResponse` is written to the response (same shape as password login).

## Configuration

| Property | Description |
|----------|-------------|
| `SPRING_PROFILES_ACTIVE` | `dev` (default) or production |
| `JWT_SECRET` | HMAC key for JWTs (min 32 chars) |
| `DB_*` | PostgreSQL when not using dev profile |
| `MAIL_*` | SMTP for magic links and email OTP |
| `MFA_SMS_PROVIDER` | `log` (dev) or `twilio` |
| `TWILIO_*` | SMS when provider is `twilio` |
| `WEBAUTHN_RP_ID` / `WEBAUTHN_ORIGIN` | Must match your frontend origin |

See `src/main/resources/application.yml` and `application-dev.yml`.

## Calling protected endpoints

```
Authorization: Bearer <accessToken>
```

Access tokens expire after `jwt.expiration` (default 1 hour). Use refresh rotation before expiry.

## Key classes (where to look)

| Question | Class |
|----------|--------|
| How is login implemented? | `service.auth.AuthenticationService` |
| How are JWTs built? | `service.auth.TokenService` |
| How does refresh rotation work? | `service.auth.RefreshTokenService` |
| How is MFA verified? | `service.mfa.MfaService` |
| How are passkeys stored? | `domain.entity.PasskeyCredential`, `service.passkey.JpaCredentialRepository` |
| What blocks unauthenticated requests? | `config.SecurityConfig`, `security.JwtAuthenticationFilter` |

## Build & test

```bash
./mvnw compile
./mvnw test
```

## License

Private / project-specific — adjust as needed.
