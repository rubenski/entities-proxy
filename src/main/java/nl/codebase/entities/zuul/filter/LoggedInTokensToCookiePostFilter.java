package nl.codebase.entities.zuul.filter;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import nl.codebase.entities.common.account.Account;
import org.apache.commons.lang3.StringUtils;
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

    // Run only for successful token requests
    @Override
    public boolean shouldFilter() {
        RequestContext context = RequestContext.getCurrentContext();
        HttpServletRequest request = context.getRequest();
        String requestURI = request.getRequestURI();
        return requestURI.contains("oauth") && context.getResponse().getStatus() == 200;
    }

    @Override
    public Object run() {
        RequestContext context = RequestContext.getCurrentContext();
        InputStream stream = context.getResponseDataStream();

        try {
            String body = StreamUtils.copyToString(stream, Charset.forName("UTF-8"));
            IAMTokenResponse IAMTokenResponse = mapper.readValue(body, IAMTokenResponse.class);
            if (IAMTokenResponse.isPresent() && IAMTokenResponse.hasAccessToken() && IAMTokenResponse.hasRefreshToken()) {
                context.getResponse().addCookie(createAccessTokenCookie(IAMTokenResponse));
                context.getResponse().addCookie(createRefreshTokenCookie(IAMTokenResponse));
                context.getResponse().addCookie(createClientReadableLoggedInCookie());
                IAMTokenResponse.clearSensitiveFields();
                context.setResponseBody(null);
            } else {
                throw new IllegalArgumentException("The token response was invalid because it was missing either the access token or the refresh token or both");
            }
        } catch (IOException e) {
            log.error("Could not deserialize token response", e);
        }

        return null;
    }

    private Cookie createRefreshTokenCookie(IAMTokenResponse IAMTokenResponse) throws IOException {
        Cookie refreshTokenCookie = new Cookie(PARAM_REFRESH_TOKEN, IAMTokenResponse.getRefreshToken());
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setMaxAge(getExpirationSecondsFromToken(IAMTokenResponse.getRefreshToken()));
        return refreshTokenCookie;
    }

    private Cookie createAccessTokenCookie(IAMTokenResponse IAMTokenResponse) throws IOException {
        Cookie accessTokenCookie = new Cookie(PARAM_ACCESS_TOKEN, IAMTokenResponse.getAccessToken());
        accessTokenCookie.setPath("/");
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setMaxAge(getExpirationSecondsFromToken(IAMTokenResponse.getAccessToken()));
        return accessTokenCookie;
    }

    private Cookie createClientReadableLoggedInCookie() {
        Cookie accessTokenCookie = new Cookie(AUTHENTICATED_COOKIE_NAME, "1");
        accessTokenCookie.setPath("/");
        accessTokenCookie.setHttpOnly(false); // This cookie must be readable by the frontend
        return accessTokenCookie;
    }

    private int getExpirationSecondsFromToken(String token)  {
        double currentEpochSeconds = Math.ceil(System.currentTimeMillis() / 1000);
        String[] tokenParts = token.split("\\.");
        String tokenPayLoadRaw = new String(Base64.getDecoder().decode(tokenParts[1]));
        TokenPayload tokenPayload = null;

        try {
            tokenPayload = mapper.readValue(tokenPayLoadRaw, TokenPayload.class);
        } catch (IOException e) {
            throw new RuntimeException("Could not deserialize a token inside the IAM token response");
        }

        int expiryEpochSeconds = tokenPayload.getExpiryEpochSeconds();
        // The expiration time is in epoch seconds format, so we must subtract the current epoch seconds to get
        // the number of seconds UNTIL expiration, which is needed by the Cookie interface.
        int i = (int) (expiryEpochSeconds - currentEpochSeconds);
        log.info("Token number of seconds valid = {}", i);
        return i;
    }


    @Getter
    @Setter
    @JsonIgnoreProperties(ignoreUnknown = true)
    private static class IAMTokenResponse {

        @JsonProperty("access_token")
        private String accessToken;

        @JsonProperty("token_type")
        private String tokenType;

        @JsonProperty("refresh_token")
        private String refreshToken;

        @JsonProperty("expires_in")
        private int expiresInSeconds;

        private Account account;

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

        public boolean hasAccessToken() {
            return !StringUtils.isBlank(accessToken);
        }

        public boolean hasRefreshToken() {
            return !StringUtils.isBlank(refreshToken);
        }

    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    @Getter
    @Setter
    private static class TokenPayload {
        @JsonProperty("exp")
        private int expiryEpochSeconds;
    }
}
