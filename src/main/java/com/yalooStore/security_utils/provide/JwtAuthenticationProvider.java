package com.yalooStore.security_utils.provide;

import java.net.URI;

import com.yalooStore.common_utils.dto.ResponseDto;
import com.yalooStore.security_utils.authenticatioToken.JwtAuthenticationToken;
import com.yalooStore.security_utils.dto.AuthorizationResponseDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationProvider implements AuthenticationProvider {

    private final RestTemplate restTemplate;
    private final String authUrl;

    @Override
    public Authentication authenticate(Authentication authentication)
            throws AuthenticationException {
        String token = (String) authentication.getCredentials();

        System.out.println("========utils authentication provider start========");

        try {
            HttpHeaders httpHeaders = new HttpHeaders();
            httpHeaders.setBearerAuth(token);
            System.out.println("shop? provider token zz"+ token);

            RequestEntity<Void> requestEntity = new RequestEntity<Void>(
                    httpHeaders,
                    HttpMethod.GET,
                    URI.create(authUrl + "/authorizations")
            );

            ResponseEntity<ResponseDto<AuthorizationResponseDto>> authorizationMetaEntity = restTemplate.exchange(
                    requestEntity,
                    new ParameterizedTypeReference<ResponseDto<AuthorizationResponseDto>>() {
                    }
            );

            AuthorizationResponseDto authorizationMeta = authorizationMetaEntity.getBody().getData();

            return JwtAuthenticationToken.authenticated(
                    token,
                    authorizationMeta.getLoginId(),
                    authorizationMeta.getAuthority()
            );
        } catch (RestClientException e) {
            throw new BadCredentialsException("invalid token : " + token);
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.isAssignableFrom(JwtAuthenticationToken.class);
    }
}