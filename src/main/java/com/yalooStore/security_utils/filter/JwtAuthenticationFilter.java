package com.yalooStore.security_utils.filter;

import com.yalooStore.security_utils.authenticatioToken.JwtAuthenticationToken;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Objects;


@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final AuthenticationManager authenticationManager;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        String token = request.getHeader("Authorization");
        System.out.println("utils auth filter -> token? " + token);

        if (Objects.isNull(token)) {
            filterChain.doFilter(request, response);
            return;
        }

        System.out.println("여기가 실행되긴 하나?? oncePerRequestFilter");
        String removePreFixToken = getRemovePreFixToken(token);

        if (Objects.isNull(removePreFixToken)){
            filterChain.doFilter(request,response);
            return;
        }

        JwtAuthenticationToken authenticationToken = JwtAuthenticationToken.unAuthenticated(removePreFixToken);
        Authentication authenticate = authenticationManager.authenticate(authenticationToken);

        SecurityContextImpl securityContext = new SecurityContextImpl(authenticate);
        SecurityContextHolder.setContext(securityContext);

        filterChain.doFilter(request, response);
    }

    public String getRemovePreFixToken(String token){
        boolean starts = token.startsWith("Bearer ");

        if (!StringUtils.hasText(token) && starts){
            return null;
        }
        return token.substring(7);
    }
}

