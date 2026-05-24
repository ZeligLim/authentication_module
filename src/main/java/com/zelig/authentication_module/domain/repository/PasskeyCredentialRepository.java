package com.zelig.authentication_module.domain.repository;

import com.zelig.authentication_module.domain.entity.PasskeyCredential;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface PasskeyCredentialRepository extends JpaRepository<PasskeyCredential, Long> {
    List<PasskeyCredential> findByUserId(Long userId);

    List<PasskeyCredential> findByUser_Username(String username);

    Optional<PasskeyCredential> findByCredentialId(String credentialId);
}