package kr.co.jwtstudy.controller;

import kr.co.jwtstudy.dto.UserDTO;
import kr.co.jwtstudy.service.UserService;
import lombok.extern.log4j.Log4j;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@Log4j2
@RestController
public class UserController {

    @Autowired
    private UserService userService;


    @GetMapping( "/index")
    public String index() {
        return "Hello World";
    }

    @PostMapping("/signup")
    public void signup(String id, String password) {

    }

    @PostMapping("/login")
    public Map<String, String> login(String id, String password) {


        try {

        }catch (Exception e) {
            log.info("error : " + e.getMessage());
        }

        return null;
    }
}