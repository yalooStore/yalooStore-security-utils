package com.yalooStore.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;
@Getter
@AllArgsConstructor
@NoArgsConstructor
public class AuthorizationResponseDto {
    private String loginId;
    private List<String> authority;

}
