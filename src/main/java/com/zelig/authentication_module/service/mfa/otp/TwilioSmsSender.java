package com.zelig.authentication_module.service.mfa.otp;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Component
@ConditionalOnProperty(name = "mfa.sms.provider", havingValue = "twilio", matchIfMissing = true)
@Slf4j
public class TwilioSmsSender implements SmsSender {

    private final RestClient restClient;

    @Value("${twilio.account-sid}")
    private String accountSid;

    @Value("${twilio.auth-token}")
    private String authToken;

    @Value("${twilio.from-number}")
    private String fromNumber;

    @Value("${app.name:Authentication Module}")
    private String appName;

    public TwilioSmsSender() {
        this.restClient = RestClient.create();
    }

    @Override
    public void sendOtp(String phoneNumber, String code, boolean enrollment) {
        if (accountSid == null || accountSid.isBlank()
                || authToken == null || authToken.isBlank()
                || fromNumber == null || fromNumber.isBlank()) {
            throw new RuntimeException("Twilio is not configured (TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM_NUMBER)");
        }

        String body = enrollment
                ? appName + " verification code: " + code
                : appName + " sign-in code: " + code;

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("To", phoneNumber);
        form.add("From", fromNumber);
        form.add("Body", body);

        String url = "https://api.twilio.com/2010-04-01/Accounts/" + accountSid + "/Messages.json";
        String basicAuth = Base64.getEncoder().encodeToString((accountSid + ":" + authToken).getBytes(StandardCharsets.UTF_8));

        restClient.post()
                .uri(url)
                .header(HttpHeaders.AUTHORIZATION, "Basic " + basicAuth)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .retrieve()
                .toBodilessEntity();

        log.info("SMS OTP sent via Twilio to {}", maskPhone(phoneNumber));
    }

    private static String maskPhone(String phone) {
        if (phone.length() <= 4) {
            return "****";
        }
        return "****" + phone.substring(phone.length() - 4);
    }
}
