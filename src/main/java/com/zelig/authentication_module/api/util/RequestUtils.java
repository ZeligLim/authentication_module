package com.zelig.authentication_module.api.util;

import jakarta.servlet.http.HttpServletRequest;

/**
 * HTTP helpers shared by REST controllers and security handlers.
 */
public final class RequestUtils {

    private RequestUtils() {
    }

    public static String userAgent(HttpServletRequest request) {
        return request.getHeader("User-Agent");
    }

    /**
     * Resolves the client IP, honoring {@code X-Forwarded-For} when behind a proxy.
     */
    public static String clientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
