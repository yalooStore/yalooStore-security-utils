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
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Objects;


@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final AuthenticationManager authenticationManager;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        String token = request.getHeader("Authorization");
        if (Objects.isNull(token)) {
            filterChain.doFilter(request, response);
            return;
        }

        JwtAuthenticationToken authenticationToken = JwtAuthenticationToken.unAuthenticated(token);

        Authentication authenticate = authenticationManager.authenticate(authenticationToken);
        SecurityContextImpl securityContext = new SecurityContextImpl(authenticate);

        SecurityContextHolder.setContext(securityContext);

        filterChain.doFilter(request, response);
    }
}

