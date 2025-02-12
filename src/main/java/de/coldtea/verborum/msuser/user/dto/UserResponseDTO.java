package de.coldtea.verborum.msuser.user.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.*;

import static de.coldtea.verborum.msuser.common.DTOMessageConstants.*;

@Data
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserResponseDTO {

    @NotBlank(message = USER_ID)
    private String wordId;

    @NotBlank(message = USER_EMAIL)
    private String email;

    @NotBlank(message = USER_PASSWORD)
    private String password;
}