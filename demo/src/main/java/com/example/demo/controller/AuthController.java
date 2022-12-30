package com.example.demo.controller;

import com.example.demo.dto.MessageResponse;
import com.example.demo.dto.SignupRequest;
import com.example.demo.enums.ERole;
import com.example.demo.models.Role;
import com.example.demo.models.User;
import com.example.demo.repository.RoleRepository;
import com.example.demo.repository.UserRepository;
import com.example.demo.security.PasswordConfig;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;
import java.util.HashSet;
import java.util.Set;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserRepository userRepository;
    private final PasswordConfig passwordConfig;

    private final RoleRepository roleRepository;

    public AuthController(UserRepository userRepository, PasswordConfig passwordConfig, RoleRepository roleRepository) {
        this.userRepository = userRepository;
        this.passwordConfig = passwordConfig;
        this.roleRepository = roleRepository;
    }

    @PostMapping
    public ResponseEntity<?> register(@Valid @RequestBody SignupRequest signupRequest) {

        if (userRepository.existsByUsername(signupRequest.getUsername())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: username already exist."));
        }

        if (userRepository.existsByEmail(signupRequest.getEmail())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: email already exist."));
        }

        User user = new User(signupRequest.getUsername(), signupRequest.getEmail(),
                passwordConfig.passwordEncoder().encode(signupRequest.getPassword()));

        Set<String> roles = signupRequest.getRole();

        Set<Role> roleSet = new HashSet<>();

        if (roles == null) {
            Role role = roleRepository.findByName(ERole.ROLE_USER).orElseThrow(
                    () -> new RuntimeException("Role not found.")
            );

            roleSet.add(role);
        } else {
            roles.forEach(
                    role -> {
                        switch (role) {
                            case "role_admin":
                                Role roleAdmin = roleRepository.findByName(ERole.ROLE_ADMIN).orElseThrow(
                                        () -> new RuntimeException("Role not found.")
                                );
                                roleSet.add(roleAdmin);
                            case "role_moderator":
                                Role roleModerator = roleRepository.findByName(ERole.ROLE_MODERATOR).orElseThrow(
                                        () -> new RuntimeException("Role not found.")
                                );
                                roleSet.add(roleModerator);
                            default:
                                Role roleUser = roleRepository.findByName(ERole.ROLE_USER).orElseThrow(
                                        () -> new RuntimeException("Role not found.")
                                );
                                roleSet.add(roleUser);
                        }
                    }
            );
        }
        user.setRoles(roleSet);
        userRepository.save(user);
        return ResponseEntity.ok(new MessageResponse("User created successfully."));
    }

}
