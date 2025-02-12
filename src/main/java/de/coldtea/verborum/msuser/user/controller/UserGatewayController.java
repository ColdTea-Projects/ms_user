package de.coldtea.verborum.msuser.user.controller;

import de.coldtea.verborum.msuser.user.dto.LoginRequestDTO;
import de.coldtea.verborum.msuser.user.dto.UserRequestDTO;
import de.coldtea.verborum.msuser.user.dto.UserResponseDTO;
import de.coldtea.verborum.msuser.user.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/user-gateway")
@Slf4j
public class UserGatewayController {

    private final UserService userService;

    public UserGatewayController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/users")
    public ResponseEntity<String> createUser(@RequestBody UserRequestDTO userRequestDTO) {
        String userId = userService.createUser(userRequestDTO);
        return ResponseEntity.ok(userId);
    }

    @GetMapping("/users/{userId}")
    public ResponseEntity<UserResponseDTO> getUser(@PathVariable String userId) {
        UserResponseDTO user = userService.getUser(userId);
        return ResponseEntity.ok(user);
    }

    @PostMapping("/access-token")
    public ResponseEntity<String> getAccessToken(@RequestBody LoginRequestDTO loginRequestDTO) {
        String token = userService.getAccessToken(loginRequestDTO.getEmail(), loginRequestDTO.getPassword());
        return ResponseEntity.ok(token);
    }
}
