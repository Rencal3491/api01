package org.zerock.api01.util;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.ZonedDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
@Log4j2
public class JWTUtil {
    @Value("${org.zerock.jwt.secret}")  //application-properties 설정된 값을 불러오는 어노테이션
    private String key;
    public String generateToken(Map<String ,Object>valueMap, int days) {
        log.info("generateKey" + key);
        //문자열 key값인 jwt token을 제공한다
        Map<String ,Object> headers = new HashMap<>();

        //헤더부분
        //헤더
        headers.put("typ", "JWT");
        headers.put("alg", "HS256");
        //payload 부분
        Map<String ,Object> payloads = new HashMap<>();
        payloads.putAll(valueMap);
        // token 생성 시간 설정
        int time = (60*24) * days;
        String jwtStr = Jwts.builder()
                .setHeader(headers)
                .setClaims(payloads)
                .setIssuedAt(Date.from(ZonedDateTime.now().toInstant()))
                .setExpiration(Date.from(ZonedDateTime.now().plusMinutes(time).toInstant()))
                .signWith(SignatureAlgorithm.HS256, key.getBytes()).compact();

        return jwtStr;
    };
    //token auth
    public Map<String , Object> validateToken(String token) throws JwtException {
        Map<String,Object> claim = null;
        claim = Jwts.parser()
                .setSigningKey(key.getBytes()).build() //set key
                .parseSignedClaims(token)
                .getBody();
        return claim;

    }
}
