package com.spring.security.springbootlogin.repository;

import com.spring.security.springbootlogin.models.ERole;
import com.spring.security.springbootlogin.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role,Long> {

    Optional<Role> findByName(ERole name);
}
