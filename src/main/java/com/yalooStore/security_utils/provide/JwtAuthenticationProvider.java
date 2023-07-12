package com.yalooStore.security_utils.provide;


import com.yalooStore.security_utils.authenticatioToken.JwtAuthenticationToken;
import com.yalooStore.common_utils.dto.ResponseDto;
import com.yalooStore.security_utils.dto.AuthorizationResponseDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.Objects;


@RequiredArgsConstructor
public class JwtAuthenticationProvider implements AuthenticationProvider {

    private final RestTemplate restTemplate;

    private final String authServerUrl;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String token = (String) authentication.getCredentials();

        System.out.println("shop provider token ======================"+token);
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.add("Authorization", token);

            RequestEntity<Void> requestEntity = new RequestEntity<>(
                    headers,
                    HttpMethod.GET,
                    URI.create(authServerUrl + "/authorizations")
            );

            ResponseEntity<ResponseDto<AuthorizationResponseDto>> responseEntity =
                    restTemplate.exchange(requestEntity,
                            new ParameterizedTypeReference<>() {
                            });

            AuthorizationResponseDto data = responseEntity.getBody().getData();

            String removePrefix = getRemovePrefixToken(token);
            return JwtAuthenticationToken.authenticated(
                    removePrefix,
                    data.getLoginId(),
                    data.getAuthority()
            );

        } catch (RestClientException e) {
            throw new BadCredentialsException("token is invalid!");
        }
    }

    private String getRemovePrefixToken(String token) {
        if (StringUtils.hasText(token) && token.startsWith("Bearer ")){
            token = token.substring(7);
        }
        throw new RestClientException("token valid exception!");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.isAssignableFrom(JwtAuthenticationToken.class);
    }
}
