package com.zelig.authentication_module.repository;

import com.zelig.authentication_module.entity.MfaMethod;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface MfaMethodRepository extends JpaRepository<MfaMethod, Long> {
    List<MfaMethod> findByUserId(Long userId);
    List<MfaMethod> findByUserIdAndIsPrimaryTrue(Long userId);
    Optional<MfaMethod> findByUserIdAndType(Long userId, MfaMethod.MfaType type);
}