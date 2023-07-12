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
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.net.URI;


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
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.add("Authorization", token);


            RequestEntity<Void> getAuthorization = new RequestEntity<>(
                    headers,
                    HttpMethod.GET,
                    URI.create(authServerUrl + "/authorizations")
            );

            ResponseEntity<ResponseDto<AuthorizationResponseDto>> responseEntity =
                    restTemplate.exchange(getAuthorization,
                            new ParameterizedTypeReference<>() {
                            });

            AuthorizationResponseDto data = responseEntity.getBody().getData();

            return JwtAuthenticationToken.authenticated(
                    token,
                    data.getLoginId(),
                    data.getAuthority()
            );

        } catch (RestClientException e) {
            throw new BadCredentialsException("token is invalid!");
        }
    }
    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.isAssignableFrom(JwtAuthenticationToken.class);
    }
}
