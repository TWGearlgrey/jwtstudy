package kr.co.jwtstudy.service;

import kr.co.jwtstudy.dto.UserDTO;
import kr.co.jwtstudy.entity.UserEntity;
import kr.co.jwtstudy.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    public UserDTO login(String id, String password) {
        UserEntity user = userRepository.findById(id).orElse(null);
        return user.toDTO();
    }

}
