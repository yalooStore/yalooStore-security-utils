package com.yalooStore.dto;

import lombok.Getter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;
@Getter
public class AuthorizationResponseDto {
    private String loginId;
    private List<String> authority;

}
