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
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String token = request.getHeader("Authorization");
        if(Objects.isNull(token)){
            logger.info("util auth filter before ======");

            filterChain.doFilter(request, response);
            return;
        }

        logger.info("util auth filter after  ======= ");

        JwtAuthenticationToken jwtAuthenticationToken = JwtAuthenticationToken.unAuthenticated(token);
        Authentication authenticate = authenticationManager.authenticate(jwtAuthenticationToken);


        SecurityContextHolder.getContext().setAuthentication(authenticate);

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        //SecurityContextImpl securityContext = new SecurityContextImpl(authenticate);
        //SecurityContextHolder.setContext(securityContext);
        logger.info("util auth filter after save auth? ======="+authentication.getPrincipal());

        filterChain.doFilter(request, response);

    }
}
