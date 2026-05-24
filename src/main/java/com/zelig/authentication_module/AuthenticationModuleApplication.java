package com.zelig.authentication_module;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Spring Boot entry point. Component scanning covers {@code com.zelig.authentication_module}
 * and all sub-packages ({@code api}, {@code service}, {@code domain}, {@code security}, {@code config}).
 *
 * @see com.zelig.authentication_module.api.controller.SessionController
 */
@SpringBootApplication
public class AuthenticationModuleApplication {

  public static void main(String[] args) {
    SpringApplication.run(AuthenticationModuleApplication.class, args);
  }

}
