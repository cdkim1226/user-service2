package com.example.userservice.service;

import com.example.userservice.dto.UserDTO;
import com.example.userservice.jpa.UserEntity;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface UserService extends UserDetailsService {
    UserDTO createUser(UserDTO userDto);

    UserDTO getUserByUserId(String userId);
    Iterable<UserEntity> getUserByAll();

    UserDTO getUserDetailsByEmail(String userName);
}
