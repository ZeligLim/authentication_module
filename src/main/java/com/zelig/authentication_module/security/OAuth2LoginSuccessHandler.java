package com.zelig.authentication_module.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zelig.authentication_module.dto.LoginResponse;
import com.zelig.authentication_module.entity.User;
import com.zelig.authentication_module.service.AuthenticationService;
import com.zelig.authentication_module.service.OAuth2Service;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final OAuth2Service oauth2Service;
    private final AuthenticationService authenticationService;
    private final ObjectMapper objectMapper;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
        OAuth2User oauth2User = token.getPrincipal();
        String provider = token.getAuthorizedClientRegistrationId();

        User user = oauth2Service.findOrCreateUser(provider, oauth2User);
        LoginResponse loginResponse = authenticationService.completeLogin(
                user,
                request.getHeader("User-Agent"),
                clientIp(request));

        response.setContentType("application/json");
        objectMapper.writeValue(response.getWriter(), loginResponse);
    }

    private static String clientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
