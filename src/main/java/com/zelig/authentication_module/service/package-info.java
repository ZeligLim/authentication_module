/**
 * Business logic, organized by feature:
 * <ul>
 *   <li>{@code auth} — sessions, JWTs, refresh rotation, magic-link email</li>
 *   <li>{@code oauth} — social account linking</li>
 *   <li>{@code mfa} — TOTP, email OTP, SMS OTP</li>
 *   <li>{@code passkey} — WebAuthn registration and authentication</li>
 * </ul>
 */
package com.zelig.authentication_module.service;
