package com.example.demo.jwt;

import com.example.demo.auth.ApplicationUser;
import com.example.demo.service.ApplicationUserService;
import com.google.common.base.Strings;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtTokenVerifier extends OncePerRequestFilter {

    private final ApplicationUserService applicationUserService;
    private static final Logger logger = LoggerFactory.getLogger(JwtTokenVerifier.class);

    public JwtTokenVerifier(ApplicationUserService applicationUserService) {
        this.applicationUserService = applicationUserService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest,
                                    HttpServletResponse httpServletResponse,
                                    FilterChain filterChain) throws ServletException, IOException {


        String authorizationHeader = httpServletRequest.getHeader("Authorization");

        if (Strings.isNullOrEmpty(authorizationHeader) || !authorizationHeader.startsWith("Bearer ")) {
            filterChain.doFilter(httpServletRequest, httpServletResponse);
            return;
        }
        String token = authorizationHeader.replace("Bearer ", "");
        validateJwtToken(token);
        try {
            String jwtSecret = "shehabshehabshehabshehabshehabshehabshehabshehabshehabshehabshehabshehabshehab";

            Jws<Claims> claimsJws = Jwts.parser().setSigningKey(Keys.hmacShaKeyFor(jwtSecret.getBytes())).parseClaimsJws(token);

            String username = claimsJws.getBody().getSubject();
            ApplicationUser user = (ApplicationUser) applicationUserService.loadUserByUsername(username);

            Authentication authenticationToken = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());

            SecurityContextHolder.getContext().setAuthentication(authenticationToken);

        } catch (JwtException e) {
            throw new IllegalStateException(String.format("Token %s can not be trust", token));
        }
        filterChain.doFilter(httpServletRequest, httpServletResponse);

    }

    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parser().parseClaimsJws(authToken);
            return true;
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }

        return false;
    }

    public String getUserNameFromJwtToken(String token, String jwtSecret) {
        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
    }
}
