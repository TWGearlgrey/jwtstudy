package kr.co.jwtstudy.controller;

import kr.co.jwtstudy.dto.UserDTO;
import kr.co.jwtstudy.entity.UserEntity;
import kr.co.jwtstudy.jwt.JwtProvider;
import kr.co.jwtstudy.security.MyUserDetails;
import kr.co.jwtstudy.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RequiredArgsConstructor
@CrossOrigin("http://localhost:5173")
@Log4j2
@RestController
public class UserController {

    private final AuthenticationManager authenticationManager;
    private final JwtProvider           jwtProvider;
    private final UserService           userService;

    @GetMapping( "/index")
    public String index() {
        return "Hello World";
    }

    @PostMapping("/signup")
    public void signup(String id, String password) {

    }

    @PostMapping("/login")
    public Map<String, String> login(@RequestBody UserDTO userDTO) {
        log.info("START!!!... login()... id :" + userDTO.getUid() + ", password : " + userDTO.getPass());

        try {
            UsernamePasswordAuthenticationToken authenticationToken
                    = new UsernamePasswordAuthenticationToken(userDTO.getUid(), userDTO.getPass());
            // UsernamePasswordAuthenticationToken의
            // Principal=test_uid, Credentials=[PROTECTED],에서
            // Principal에 uid, Credentials에 pass input.
            log.info(" - login... 1.1. authenticationToken : " + authenticationToken);

            Authentication authentication = authenticationManager.authenticate(authenticationToken);
            // 위 코드에서 Authentication Manager ->

            log.info(" - login... 1.2. authentication : " + authentication);
            MyUserDetails  userDetails    = (MyUserDetails) authentication.getPrincipal();
            log.info(" - login... 1.3. userDetails    : " + userDetails);

            UserEntity user = userDetails.getUser();
            log.info(" - login... 1.4. user : " + user);

            String accessToken  = jwtProvider.createToken(user, 1) ;
            String refreshToken = jwtProvider.createToken(user, 3) ;
            log.info(" - login... 1.5. accessToken  : " + accessToken);
            log.info(" - login... 1.6. refreshToken : " + refreshToken);


            // 합치지 말고 accessToken, refreshToken을 나누는 것이 좋아 보임.
            Map<String, String> result = Map.of("grantType", "Bearer",
                                                "accessToken",   accessToken,
                                                "refreshToken",  refreshToken);
            log.info(" - login... 1.7. result : " + result);

            return result;

        }catch (Exception e) {
            log.info("error : " + e.getMessage());
            Map<String, String> result = Map.of("grantType", "none", "message", e.getMessage());

            return result;
        }
    }

    @CrossOrigin("http://localhost:5173")
    @GetMapping("/user")
    public List<UserEntity> getUsers() {
        return userService.getUsers();
    }

    @CrossOrigin("http://localhost:5173")
    @GetMapping("/user/{id}")
    public UserEntity getUser(@PathVariable String id) {
        return userService.getUser(id);
    }

    @CrossOrigin("http://localhost:5173")
    @PostMapping("/user")
    public void inputUser(@RequestBody UserEntity entity) {
        log.info("Inserting");
        userService.insertUser(entity);
    }
    @CrossOrigin("http://localhost:5173")
    @PutMapping("/user")
    public void modifyUser(@RequestBody UserEntity entity) {
        log.info("Modifying");
        userService.insertUser(entity);
    }

    @CrossOrigin("http://localhost:5173")
    @DeleteMapping("/user/{id}")
    public void deleteUser(@PathVariable String id) {
        userService.deleteUser(id);
    }


}