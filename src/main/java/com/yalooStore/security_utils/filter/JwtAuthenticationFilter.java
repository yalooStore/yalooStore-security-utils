package com.yalooStore.security_utils.filter;

import com.yalooStore.security_utils.authenticatioToken.JwtAuthenticationToken;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Objects;


@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final AuthenticationManager authenticationManager;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String token = parseJwt(request);

        if(Objects.isNull(token)){
            filterChain.doFilter(request, response);
        }

        JwtAuthenticationToken authenticationToken = JwtAuthenticationToken.unAuthenticated(token);
        Authentication authenticate = authenticationManager.authenticate(authenticationToken);

        SecurityContextImpl securityContext = new SecurityContextImpl(authenticate);
        SecurityContextHolder.setContext(securityContext);

        filterChain.doFilter(request, response);
    }

    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");
        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")){
            return headerAuth;
        }
        return null;
    }

}
