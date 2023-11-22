package kr.co.jwtstudy.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Log4j2
@RequiredArgsConstructor
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtProvider jwtProvider;
    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String TOKEN_PREFIX         = "Bearer ";


    public String getTokenFromHeader(String header) {
        log.info(" - START!!!...jwt.getTokenFromHeader()...");
        // 접두어 Bearer 제거 후 토큰 값 반환
        if(header != null && header.startsWith(TOKEN_PREFIX)) {
            log.info(" -- getTokenFromHeader 1.1. header is not null.. or header is 'bearer'..");
            log.info(" - EEEND!!!...jwt.getTokenFromHeader()...");
            return header.substring(TOKEN_PREFIX.length());
        }
        log.info(" -- getTokenFromHeader 1.2. header : " + header);
        log.info(" - EEEND!!!...jwt.getTokenFromHeader()...");
        return null;
    }


    // HTTP 요청을 필터링 및 처리
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {
        log.info("START!!!...jwt.JwtAuthenticationFilter.doFilterInternal()...");

        String header = request.getHeader(AUTHORIZATION_HEADER);
        log.info(" - doFilterInternal 1.1. header : " + header);

        String token = getTokenFromHeader(header);
        log.info(" - doFilterInternal 1.2. token : " + token);

        // token이 존재하고 유효한 경우.
        if(token != null && jwtProvider.validateToken(token)) {
            log.info(" - doFilterInternal 2.1. token is not null.. or validation failed..");

            // Security 인증처리
            Authentication authentication = jwtProvider.getAuthentication(token);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            log.info(" - doFilterInternal 2.2. authentication : " + authentication);
            log.info(" - doFilterInternal 2.3. SecurityContextHolder.getContext().getAuthentication() : " + SecurityContextHolder.getContext().getAuthentication());
        }
        filterChain.doFilter(request, response);
        log.info("EEEND!!!...jwt.JwtAuthenticationFilter.doFilterInternal()...");
    }

}