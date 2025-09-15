package com.authsystem.api.repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.authsystem.api.entity.User;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    Optional<User> findByUsername(String username);
    Optional<User> findByEmail(String email);
    Optional<User> findByMobile(String mobile);

    Optional<User> findByUsernameOrEmailOrMobile(String username, String email, String mobile);

    boolean existsByUsername(String username);
    boolean existsByEmail(String email);
    boolean existsByMobile(String mobile);

    List<User> findByEnabledTrue();
    List<User> findByEnabledFalse();
    List<User> findByCreatedAtAfter(LocalDateTime date);

    // Removed search by firstName/lastName
    // If needed in future, could search by username or email instead

    @Query("SELECT COUNT(u) FROM User u WHERE u.enabled = true")
    Long countEnabledUsers();

    @Query("SELECT u FROM User u WHERE u.lastLogin < :date OR u.lastLogin IS NULL")
    List<User> findInactiveUsers(@Param("date") LocalDateTime date);
}
