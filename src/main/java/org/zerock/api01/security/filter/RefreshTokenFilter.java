package org.zerock.api01.security.filter;

import com.google.gson.Gson;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.parameters.P;
import org.springframework.web.filter.OncePerRequestFilter;
import org.zerock.api01.security.exception.RefreshTokenException;
import org.zerock.api01.util.JWTUtil;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.Map;

@Log4j2
@RequiredArgsConstructor
public class RefreshTokenFilter extends OncePerRequestFilter {

    private final String refreshPath;
    private final JWTUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String path = request.getRequestURI();
        if(!path.equals(refreshPath)) {
            log.info("Skip refresh token filter");
            filterChain.doFilter(request,response);
            return;
        }
        log.info("Refresh_Token_filter_run___");
        //검증
        //JSON 형식으로 전송된 accessToken과 resfreshToken 받기
        Map<String ,String> tokens = parseRequestJSON(request);

        String accessToken =  tokens.get("accessToken");
        String refreshToken = tokens.get("refreshToken");

        log.info("accessToken : " + accessToken);
        log.info("refreshToken : " + refreshToken);

        try {
            checkAccessToken(accessToken);      //accessToken 만료시에는 RefreshTokenException으로 전달되지 않음
        }catch (RefreshTokenException refreshTokenException) {
            refreshTokenException.sendResponseError(response);
            return;
        }

        Map<String ,Object> refreshClaims = null;

        try {
            refreshClaims = checkRefreshToken(refreshToken);
            log.info(refreshClaims);
        } catch (RefreshTokenException refreshTokenException) {
            refreshTokenException.sendResponseError(response);
            return;
        }
    }

    private Map<String ,String> parseRequestJSON(HttpServletRequest request) {

        try (Reader reader = new InputStreamReader(request.getInputStream())){
            Gson gson = new Gson();
            return gson.fromJson(reader,Map.class);
        } catch (Exception e) {
            log.error(e.getMessage());
        }
        return null;

    }

    //AccessToken 검증
    private void checkAccessToken(String accessToken)throws RefreshTokenException {

        try {
            jwtUtil.validateToken(accessToken); //토큰 검증
        }catch (ExpiredJwtException expiredJwtException) {
            log.info("AccessToken has expired..");
        }catch (Exception e) {
            //Access Token 만료 이외의 예외처리
            throw new RefreshTokenException(RefreshTokenException.ErrorCase.NO_ACCESS);
        }
    }

    //AccessToken 검증
    private Map<String ,Object> checkRefreshToken(String refreshToken)throws RefreshTokenException {
        try {
           Map<String ,Object> values = jwtUtil.validateToken(refreshToken); //토큰 검증
            return values;
        }catch (ExpiredJwtException expiredJwtException) {
            throw new RefreshTokenException(RefreshTokenException.ErrorCase.OLD_REFRESH);
        }catch (MalformedJwtException malformedJwtException) {
            log.error("MalformedJwtException..");
            throw new RefreshTokenException(RefreshTokenException.ErrorCase.NO_REFRESH);
        }catch (Exception e) {
            new RefreshTokenException(RefreshTokenException.ErrorCase.NO_REFRESH);
        }
        return null;
    }
}
