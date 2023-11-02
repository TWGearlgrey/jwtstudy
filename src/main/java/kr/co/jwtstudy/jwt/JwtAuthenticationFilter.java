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

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {
        log.info("JwtAuthenticationFilter...1");

        String header = request.getHeader(AUTHORIZATION_HEADER);
        log.info("JwtAuthenticationFilter...2 : " + header);

        String token = getTokenFromHeader(header);
        log.info("JwtAuthenticationFilter...3 : " + token);

        // token이 없거나 유효하지 않은 경우.
        if(token == null ||!jwtProvider.validateToken(token)) {
            log.info("JwtAuthenticationFilter...4");

            // Security 인증처리
            Authentication authentication = jwtProvider.getAuthentication(token);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        log.info("JwtAuthenticationFilter...5");
        filterChain.doFilter(request, response);
    }

    public String getTokenFromHeader(String header) {
        // 접두어 Bearer 제거 후 토큰 값 반환
        if(header != null && header.startsWith(TOKEN_PREFIX)) {
            return header.substring(TOKEN_PREFIX.length());
        }
        return null;
    }

}
