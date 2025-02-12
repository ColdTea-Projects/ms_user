package de.coldtea.verborum.msuser.user.service;

import de.coldtea.verborum.msuser.user.dto.UserRequestDTO;
import de.coldtea.verborum.msuser.user.dto.UserResponseDTO;

public interface UserService {
    /**
     * Creates a new user in Keycloak
     *
     * @param userRequestDTO Contains user information (email, password, firstName, lastName)
     * @return String The ID of the created user
     * @throws RuntimeException if user creation fails
     */
    String createUser(UserRequestDTO userRequestDTO);

    /**
     * Retrieves user information from Keycloak by user ID
     *
     * @param userId The ID of the user to retrieve
     * @return UserRepresentation containing user details
     * @throws RuntimeException if user retrieval fails
     */
    UserResponseDTO getUser(String userId);

    /**
     * Gets an access token for the user using their credentials
     *
     * @param username User's email/username
     * @param password User's password
     * @return String JWT access token
     * @throws RuntimeException if token retrieval fails
     */
    String getAccessToken(String username, String password);
}