package kr.co.jwtstudy.security;

import kr.co.jwtstudy.entity.UserEntity;
import kr.co.jwtstudy.repository.UserRepository;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Log4j2
@Service
public class SecurityUserService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

     @Override
     public UserDetails loadUserByUsername(String uid) throws UsernameNotFoundException {
         log.info("START!!!...SecurityUserService.loadUserByUsername()...");
         // AuthenticationProvider에서 비밀번호를 체크 후 UserDetailService가 생성
         // 이후 UserDetailService에서 UserDetails 객체를 생성.

         // 패스워드에 대한 검사는 컴포넌트(AuthenticationProvider에서 처리되어 사용자 아이디만 넘어옴)
         log.info(" - loadUserByUsername() 1.1. uid : " + uid);
         UserEntity user = userRepository.findById(uid).orElse(null);
         log.info(" - loadUserByUsername() 1.2. user : " + user);

         // 사용자 인증 객체 생성(세션에 저장)
         UserDetails userDetails = MyUserDetails.builder()
                 .user(user)
                 .build();
         log.info(" - loadUserByUsername() 2.1. userDetails : " + userDetails);
         log.info("EEEND!!!...SecurityUserService.loadUserByUsername()...");

         return userDetails;
     }
}
