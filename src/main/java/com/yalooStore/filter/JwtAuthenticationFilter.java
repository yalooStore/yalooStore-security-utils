package com.yalooStore.filter;

import com.yalooStore.authenticatioToken.JwtAuthenticationToken;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Objects;


@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final AuthenticationManager authenticationManager;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        if(Objects.isNull(request.getHeader("Authorization"))){
            filterChain.doFilter(request, response);
            return;
        }
        String token = request.getHeader("Authorization");

        JwtAuthenticationToken jwtAuthenticationToken = JwtAuthenticationToken.unAuthenticated(token);

        authenticationManager.authenticate(jwtAuthenticationToken);
        SecurityContextImpl securityContext = new SecurityContextImpl(jwtAuthenticationToken);
        SecurityContextHolder.setContext(securityContext);

        filterChain.doFilter(request, response);

    }
}
