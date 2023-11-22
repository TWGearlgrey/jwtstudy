package kr.co.jwtstudy.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import kr.co.jwtstudy.entity.UserEntity;
import lombok.Getter;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.time.Duration;
import java.util.Collections;
import java.util.Date;

@Log4j2
@Getter
@Component
public class JwtProvider {

    private String    issuer;
    private SecretKey secretKey;

    // issuer, secret key 값 load
    public JwtProvider(@Value("${jwt.issuer}") String issuer,
                       @Value("${jwt.secret}") String secret) {
        this.issuer    = issuer;
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes());
    }

    // token 생성
    public String createToken(UserEntity user, int min) {
        log.info("START!!!...jwt.JwtProvider.createToken()");

        // 생성일, 만료일(1시간) 생성
        Date issuredDate = new Date();
        Date expiredDate = new Date(issuredDate.getTime()
            + Duration.ofDays(min).toMillis()/1440);
        log.info(" - createToken() 1.1. issuredDate : " + issuredDate);
        log.info(" - createToken() 1.2. expiredDate : " + expiredDate);

        // jwt 클레임 생성
        Claims claims = Jwts.claims();
        claims.put("uid",  user.getUid());
        claims.put("role", user.getRole());
        log.info(" - createToken() 2.1. claims : " + claims);

        // JSON Web Token 생성
        String token = Jwts.builder()
            // token type set(jwt)
            .setHeaderParam(Header.TYPE, Header.JWT_TYPE)
            // 발급자 set(jwt.issuer)
            .setIssuer(issuer)
            // 발급시간 set
            .setIssuedAt(issuredDate)
            // 만료시간 set(발급시간 + 1시간)
            .setExpiration(expiredDate)
            // jwt payload set(claims)
            .addClaims(claims)
            // sign secretKey set(jwt.secret)
            .signWith(secretKey, SignatureAlgorithm.HS256)
            // parse to String
            .compact();
        log.info(" - createToken() 3.1. token : " + token);
        log.info("EEEND!!!...jwt.JwtProvider.createToken()");
        return token;
    }

    // authentication 객체 생성
    public Authentication getAuthentication(String token) {
        log.info("START!!!...jwt.JwtProvider.getAuthentication()...");
        // getClaims method로 token secretKey 검증 후 payload 추출.
        Claims claims = getClaims(token);
        log.info(" - getAuthentication() 1.1. claims : " + claims);
        // payload에서 uid, role 추출
        String uid  = (String) claims.get("uid");
        String role = (String) claims.get("role");
        log.info(" - getAuthentication() 1.2. uid  : " + uid);
        log.info(" - getAuthentication() 1.3. role : " + role);

        /* CASE1. 유저가 여러개의 권한을 가질 때.
        // GrantedAuthority는 Spring security에서 권한을 확인하기 위한 인터페이스.
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_" + role));

        // user 객체 생성 (uid, password, role 순서)
        // role은 하나인데 왜 List를 사용? -> 사용자가 여러가지 권한을 가질 수도 있으므로.
        User principal = new User(uid, "", authorities);
        */

        /* CASE2. 유저가 하나의 권한을 가질 때  */
        GrantedAuthority authority = new SimpleGrantedAuthority("ROLE_" + role);
        log.info(" - getAuthentication() 2.1. authority :" + authority);

        // user 객체 생성 (uid, password, role 순서)
        User principal = new User(uid, "", Collections.singletonList(authority));
        log.info(" - getAuthentication() 2.2. principal : " + principal);

        log.info("EEEND!!!...jwt.JwtProvider.getAuthentication()...");
        // Spring security의 사용자 인증정보를 나타내는 UsernamePasswordAuthenticationToken Class
        // 사용자 정보를 담는 principal, 사용자의 비밀번호를 나타내는 credentials, 권한 정보를 나타내는 authority
        return new UsernamePasswordAuthenticationToken(principal, token, Collections.singletonList(authority));
    }

    // 토큰 검사 메서드
    public boolean validateToken(String token) {
        log.info("START!!!...jwt.JwtProvider.validateToken()...");
        try {
            log.info(" - validateToken() 1.1. token : " + token);
            Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token);
            log.info("EEEND!!!...jwt.JwtProvider.validateToken()...token is true");
            return true;

        } catch (SecurityException | MalformedJwtException e) {
            log.info("잘못된 JWT 서명입니다. : " + e.getMessage());

        } catch (ExpiredJwtException e) {
            log.info("만료된 JWT 서명입니다. : " + e.getMessage());

        } catch (UnsupportedJwtException e) {
            log.info("지원되지 않는 JWT 서명입니다. : " + e.getMessage());

        } catch (IllegalArgumentException e) {
            log.info("JWT 토큰이 잘 못 되었습니다. : " + e.getMessage());
        }
        log.info("EEEND!!!...jwt.JwtProvider.validateToken()...token is false");
        return false;
    }

    // JSON Web Token에서 claims 추출.
    public Claims getClaims(String token) {
        log.info("START!!!...jwt.JwtProvider.getClaims()...");
        log.info(" - getClaims() 1.1. token : " + token);
        log.info("EEEND!!!...jwt.JwtProvider.getClaims()...");
        return Jwts.parserBuilder()
                // 서명 확인을 위해 secretKey set(jwt.secret)
                .setSigningKey(secretKey)
                // parser 객체 생성 완료.
                .build()
                // token을 parsing 및 서명 확인 후 JWS(JSON Web Signature) 객체 반환
                .parseClaimsJws(token)
                // JWS 객체에서 payload(claims) 추출.
                .getBody();
    }
}