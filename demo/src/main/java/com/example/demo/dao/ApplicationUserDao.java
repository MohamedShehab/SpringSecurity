package com.example.demo.dao;

import com.example.demo.auth.ApplicationUser;

import java.util.Optional;

public interface ApplicationUserDao {

    Optional<ApplicationUser> selectApplicationUserByUsername(String username);
}
