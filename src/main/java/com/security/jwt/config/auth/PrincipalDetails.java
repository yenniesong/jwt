package com.security.jwt.config.auth;

import com.security.jwt.model.JwtUser;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
@Data
public class PrincipalDetails implements UserDetails {

    private JwtUser jwtUser;

    public PrincipalDetails(JwtUser jwtUser) {
        this.jwtUser = jwtUser;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        jwtUser.getRoleList().forEach(r-> {
            authorities.add(()-> {
                return r;
            });
        });
        return authorities;
    }

    @Override
    public String getPassword() {
        return jwtUser.getPassword();
    }

    @Override
    public String getUsername() {
        return jwtUser.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
