package de.coldtea.verborum.msuser.user.dto;

import jakarta.validation.constraints.NotEmpty;
import lombok.*;

import static de.coldtea.verborum.msuser.common.DTOMessageConstants.USER_EMAIL;
import static de.coldtea.verborum.msuser.common.DTOMessageConstants.USER_PASSWORD;

@Data
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LoginRequestDTO {

    @NotEmpty(message = USER_EMAIL)
    private String email;

    @NotEmpty(message = USER_PASSWORD)
    private String password;
}