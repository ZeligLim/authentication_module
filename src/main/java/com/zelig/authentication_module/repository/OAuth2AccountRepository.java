package com.zelig.authentication_module.repository;

import com.zelig.authentication_module.entity.OAuth2Account;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.List;

@Repository
public interface OAuth2AccountRepository extends JpaRepository<OAuth2Account, Long> {
    Optional<OAuth2Account> findByProviderAndProviderUserId(String provider, String providerUserId);
    List<OAuth2Account> findByUserId(Long userId);
}