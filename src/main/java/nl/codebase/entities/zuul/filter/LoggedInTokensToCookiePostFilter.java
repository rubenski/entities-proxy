package nl.codebase.entities.zuul.filter;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.StreamUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.Base64;

import static nl.codebase.entities.common.FaceterConstants.AUTHENTICATED_COOKIE_NAME;
import static nl.codebase.entities.common.FaceterConstants.PARAM_ACCESS_TOKEN;
import static nl.codebase.entities.common.FaceterConstants.PARAM_REFRESH_TOKEN;



/**
 * Moves the refresh and access tokens created by Spring security after successful authentication from the response
 * body into HTTP-only time-limited cookies. We prefer having tokens in HTTP-only cookies, because storing tokens
 * in browser storage will make them vulnerable to cross site scripting attacks.
 *
 * We provide a cross site request forgery (CSRF) token to protect against abuse of the created cookies. See
 * CsrfTokenResponseFilter.
 */
@Slf4j
@Component
public class LoggedInTokensToCookiePostFilter extends ZuulFilter {

    private ObjectMapper mapper = new ObjectMapper();

    @Override
    public String filterType() {
        return "post";
    }

    @Override
    public int filterOrder() {
        return 10;
    }

    @Override
    public boolean shouldFilter() {
        RequestContext context = RequestContext.getCurrentContext();
        HttpServletRequest request = context.getRequest();
        String requestURI = request.getRequestURI();
        return requestURI.contains("oauth");
    }

    @Override
    public Object run() {
        RequestContext context = RequestContext.getCurrentContext();
        InputStream stream = context.getResponseDataStream();

        try {
            String body = StreamUtils.copyToString(stream, Charset.forName("UTF-8"));
            AccessToken accessToken = mapper.readValue(body, AccessToken.class);
            if (accessToken.isPresent()) {
                context.getResponse().addCookie(createAccessTokenCookie(accessToken));
                context.getResponse().addCookie(createRefreshTokenCookie(accessToken));
                context.getResponse().addCookie(createClientReadableLoggedInCookie());
                accessToken.clearSensitiveFields();
                context.setResponseBody(null);
            }
        } catch (IOException e) {
            log.error("Cannot deserialize token response", e);
        }

        return null;
    }

    private Cookie createRefreshTokenCookie(AccessToken accessToken) throws IOException {
        Cookie refreshTokenCookie = new Cookie(PARAM_REFRESH_TOKEN, accessToken.getRefreshToken());
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setMaxAge(getExpirationSecondsFromToken(accessToken.getRefreshToken()));
        return refreshTokenCookie;
    }

    private Cookie createAccessTokenCookie(AccessToken accessToken) throws IOException {
        Cookie accessTokenCookie = new Cookie(PARAM_ACCESS_TOKEN, accessToken.getAccessToken());
        accessTokenCookie.setPath("/");
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setMaxAge(getExpirationSecondsFromToken(accessToken.getAccessToken()));
        return accessTokenCookie;
    }

    private Cookie createClientReadableLoggedInCookie() {
        Cookie accessTokenCookie = new Cookie(AUTHENTICATED_COOKIE_NAME, null);
        accessTokenCookie.setPath("/");
        accessTokenCookie.setHttpOnly(false); // This cookie must be readable by the frontend
        return accessTokenCookie;
    }

    private int getExpirationSecondsFromToken(String accessToken) throws IOException {
        double currentEpochSeconds = Math.ceil(System.currentTimeMillis() / 1000);
        String[] refreshTokenParts = accessToken.split("\\.");
        String refreshTokenPayloadRaw = new String(Base64.getDecoder().decode(refreshTokenParts[1]));
        RefreshTokenPayload refreshTokenPayload = mapper.readValue(refreshTokenPayloadRaw, RefreshTokenPayload.class);
        int expiryEpochSeconds = refreshTokenPayload.getExpiryEpochSeconds();
        // The expiration time is in epoch seconds format, so we must subtract the current epoch seconds to get
        // the number of seconds UNTIL expiration, which is needed by the Cookie interface.
        int i = (int) (expiryEpochSeconds - currentEpochSeconds);
        log.info("Token number of seconds valid = {}", i);
        return i;
    }


    @Getter
    @Setter
    private static class AccessToken {

        @JsonProperty("access_token")
        private String accessToken;

        @JsonProperty("token_type")
        private String tokenType;

        @JsonProperty("refresh_token")
        private String refreshToken;

        @JsonProperty("expires_in")
        private int expiresInSeconds;

        private String scope;
        private String jti;
        private String error;
        @JsonProperty("error_description")
        private String errorDescription;

        boolean noError() {
            return error == null;
        }

        boolean isPresent() {
            return accessToken != null;
        }

        void clearSensitiveFields() {
            refreshToken = null;
            accessToken = null;
        }

    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    @Getter
    @Setter
    private static class RefreshTokenPayload {
        @JsonProperty("exp")
        private int expiryEpochSeconds;
    }
}
