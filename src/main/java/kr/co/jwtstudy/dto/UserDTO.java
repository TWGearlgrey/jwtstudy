package kr.co.jwtstudy.dto;

import kr.co.jwtstudy.entity.UserEntity;
import lombok.*;


@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@ToString
public class UserDTO {
    private String uid;
    private String pass;
    private String role;

    public UserEntity toEntity() {
        return UserEntity
            .builder()
            .uid(uid)
            .pass(pass)
            .role(role)
            .build();
    }
}
