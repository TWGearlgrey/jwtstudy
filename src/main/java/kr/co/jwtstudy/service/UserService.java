package kr.co.jwtstudy.service;

import kr.co.jwtstudy.dto.UserDTO;
import kr.co.jwtstudy.entity.UserEntity;
import kr.co.jwtstudy.repository.UserRepository;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.beans.Transient;
import java.util.List;

@Log4j2
@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    public UserDTO login(String id, String password) {
        UserEntity user = userRepository.findById(id).orElse(null);
        return user.toDTO();
    }

    public List<UserEntity> getUsers() {
        return userRepository.findAll();
    }
    public UserEntity getUser(String id) {
        log.info("getUser");
        return userRepository.findById(id).orElse(null);
    }

    public void insertUser(UserEntity entity) {
        log.info("insertUser");
        userRepository.save(entity);
    }

    @Transient
    public void deleteUser(String id) {
        log.info("deleteUser");
        userRepository.deleteById(id);
    }
}