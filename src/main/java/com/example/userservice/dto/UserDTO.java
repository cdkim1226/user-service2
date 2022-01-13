package com.example.userservice.dto;

import com.example.userservice.vo.ResponseOrder;
import lombok.Data;

import java.util.List;

@Data
public class UserDTO {
    private String email;
    private String name;
    private String pwd;
    private String userId;
    private Data createdAt;

    private String encryptedPwd;

    private List<ResponseOrder> orders;

}
