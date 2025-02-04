package com.kamil.auth_service.security;

import com.kamil.auth_service.model.Role;
import com.kamil.auth_service.model.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

public class JwtUserDetails implements UserDetails {

    private final String email;
    private final String password;
    private final Set<Role> roles;

    public JwtUserDetails(User user) {
        this.email = user.getEmail();
        this.password = user.getPassword();
        this.roles = user.getRole();
    }


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.name()))
                .collect(Collectors.toList());
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return email;
    }
}
