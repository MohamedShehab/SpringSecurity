package com.example.demo.auth;

import com.example.demo.models.Role;
import com.example.demo.models.User;
import com.fasterxml.jackson.annotation.JsonIgnore;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

public class ApplicationUser implements UserDetails {

    private final Set<? extends GrantedAuthority> grantedAuthorities;
    private final String username;
    @JsonIgnore
    private final String password;
    private final boolean isAccountNonExpired;
    private final boolean isAccountNonLocked;
    private final boolean isCredentialsNonExpired;
    private final boolean isEnabled;


    public ApplicationUser(
            Set<? extends GrantedAuthority> grantedAuthorities,
            String username,
            String password,
            boolean isAccountNonExpired,
            boolean isAccountNonLocked,
            boolean isCredentialsNonExpired,
            boolean isEnabled
    ) {
        this.grantedAuthorities = grantedAuthorities;
        this.username = username;
        this.password = password;
        this.isAccountNonExpired = isAccountNonExpired;
        this.isAccountNonLocked = isAccountNonLocked;
        this.isCredentialsNonExpired = isCredentialsNonExpired;
        this.isEnabled = isEnabled;
    }

    public static ApplicationUser build(User user) {
        Set<Role> roles = user.getRoles();

        Set<GrantedAuthority> grantedAuthorities = roles.stream().map(
                role -> new SimpleGrantedAuthority(role.getName().name())
        ).collect(Collectors.toSet());

        return new ApplicationUser(
                grantedAuthorities, user.getUsername(), user.getPassword(), true, true, true, true
        );
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return grantedAuthorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return isAccountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return isAccountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return isCredentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return isEnabled;
    }
}
