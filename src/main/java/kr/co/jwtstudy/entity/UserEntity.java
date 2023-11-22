package kr.co.jwtstudy.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import kr.co.jwtstudy.dto.UserDTO;
import lombok.*;

@NoArgsConstructor
@AllArgsConstructor
@Builder
@ToString
@Data
@Entity
@Table(name = "User")
public class UserEntity {

    @Id
    private String uid;
    private String pass;
    private String role;
    private String name;
    private String hp;
    private int    age;

    public UserDTO toDTO() {
        return UserDTO
            .builder()
            .uid(uid)
            .role(role)
            .build();
    }

}
