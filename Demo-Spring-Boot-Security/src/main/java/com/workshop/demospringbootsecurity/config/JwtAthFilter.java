//package com.workshop.demospringbootsecurity.config;
//
//import jakarta.servlet.FilterChain;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
//import org.springframework.web.filter.OncePerRequestFilter;
//
//import java.io.IOException;
//
//import static org.springframework.http.HttpHeaders.AUTHORIZATION;
//
//public class JwtAthFilter extends OncePerRequestFilter {
//
//    private UserDetailsService userDetailsService;
//
//    @Override
//    protected void doFilterInternal(HttpServletRequest request
//            , HttpServletResponse response,
//                                    FilterChain filterChain) throws ServletException, IOException {
//
//        final String authHeader = request.getHeader(AUTHORIZATION);
//        final String userEmail;
//        final String jwtToken;
//
//        if (authHeader == null || !authHeader.startsWith("Bearer")) {
//            filterChain.doFilter(request, response);
//            return;
//        }
//
//        jwtToken = authHeader.substring(7);
//        userEmail = "something";
//        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
//            UserDetails usersDetails = userDetailsService.loadUserByUsername(userEmail);
//            final boolean isTokenValid;
//            if (isTokenValid) {
//                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
//                        usersDetails, null, usersDetails.getAuthorities()
//                );
//                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
//            }
//        }
//
//        filterChain.doFilter(request, response);
//
//    }
//}
