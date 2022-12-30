package com.spring.security.springbootlogin.controllers;

import com.spring.security.springbootlogin.jwt.JwtUtils;
import com.spring.security.springbootlogin.models.ERole;
import com.spring.security.springbootlogin.models.Role;
import com.spring.security.springbootlogin.models.User;
import com.spring.security.springbootlogin.payload.request.LoginRequest;
import com.spring.security.springbootlogin.payload.request.SignupRequest;
import com.spring.security.springbootlogin.payload.response.MessageResponse;
import com.spring.security.springbootlogin.payload.response.UserInfoResponse;
import com.spring.security.springbootlogin.repository.RoleRepository;
import com.spring.security.springbootlogin.repository.UserRepository;
import com.spring.security.springbootlogin.services.UserDetailsImpl;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {


    AuthenticationManager authenticationManager;
    UserRepository userRepository;
    RoleRepository roleRepository;
    PasswordEncoder encoder;
    JwtUtils jwtUtils;

    @Autowired
    public AuthController(AuthenticationManager authenticationManager, UserRepository userRepository, RoleRepository roleRepository, PasswordEncoder encoder, JwtUtils jwtUtils) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.encoder = encoder;
        this.jwtUtils = jwtUtils;
    }

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(userDetails);

        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
                .body(new UserInfoResponse(
                        userDetails.getId(),
                        userDetails.getUsername(),
                        userDetails.getEmail(),
                        roles));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> register(@Valid @RequestBody SignupRequest signupRequest) {

        if (userRepository.existsByUsername(signupRequest.getUsername())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(signupRequest.getEmail())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));
        }

        User user = new User(
                signupRequest.getUsername(), signupRequest.getEmail(),
                encoder.encode(signupRequest.getPassword())
        );

        Set<String> signRoles = signupRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (signRoles == null) {
            Role role = roleRepository.findByName(ERole.ROLE_USER).orElseThrow(
                    () -> new RuntimeException("Error: Role is not found.")
            );
            roles.add(role);
        } else {
            signRoles.forEach(
                    role -> {
                        switch (role) {
                            case "admin" -> {
                                Role admin = roleRepository.findByName(ERole.ROLE_ADMIN).orElseThrow(
                                        () -> new RuntimeException("Error: Role is not found.")
                                );
                                roles.add(admin);
                            }
                            case "mod" -> {
                                Role mod = roleRepository.findByName(ERole.ROLE_MODERATOR).orElseThrow(
                                        () -> new RuntimeException("Error: Role is not found.")
                                );
                                roles.add(mod);
                            }
                            default -> {
                                Role roleUser = roleRepository.findByName(ERole.ROLE_USER).orElseThrow(
                                        () -> new RuntimeException("Error: Role is not found.")
                                );
                                roles.add(roleUser);
                            }
                        }
                    });
        }
        user.setRoles(roles);
        userRepository.save(user);
        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

    @PostMapping("/signout")
    public ResponseEntity<?> logoutUser() {
        ResponseCookie cookie = jwtUtils.getCleanJwtCookie();
        return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(new MessageResponse("You've been signed out!"));
    }
//
//    @GetMapping("/token/{username}")
//    public ResponseEntity<?> generateToken(@PathVariable String username){
//        String jwt = jwtUtils.generateTokenFromUsername(username);
//        return ResponseEntity.ok("Token:" + jwt);
//    }

}
