package kr.co.jwtstudy.repository;

import kr.co.jwtstudy.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, String> {

}
