package kr.co.jwtstudy.security;

import kr.co.jwtstudy.entity.UserEntity;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Log4j2
@Getter
@Setter
@Builder
@ToString
public class MyUserDetails implements UserDetails {

    private UserEntity user;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        log.info("START!!!...MyUserDetails.getAuthorities()...");
        log.info(" - getAuthorities() 1.1. user : " + user);
        log.info(" - getAuthorities() 1.2. role : " + user.getRole());
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_" + user.getRole()));
        // hasRole(), hasAndRole() 사용할 경우 "ROLE_"을 넣을 것.
        // hasAuthority(), hasAnyAuthority() 사용할 시 생략 해도 됨.

        log.info(" - getAuthorities() 2.1. authorities : " + authorities);
        log.info("EEEND!!!...MyUserDetails.getAuthorities()...");
        return authorities;
    }

    @Override
    public String getPassword() {
        // 계정이 갖는 비밀번호
        return user.getPass();
    }

    @Override
    public String getUsername() {
        // 계정이 갖는 아이디
        return user.getUid();
    }

    @Override
    public boolean isAccountNonExpired() {
        // 계정 만료 여부(true:만료 안 됨, false:만료)
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        // 계정 잠김 여부(true:잠김 안 됨, false:잠김)
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        // 계정 비밀번호 만료 여부(true:만료 안 됨, false:만료)
        return true;
    }

    @Override
    public boolean isEnabled() {
        // 계정 활성화 여부(true:활성화, false:비활성화)
        return true;
    }
}
