package nl.codebase.entities.zuul.filter;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.exception.ZuulException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.netflix.zuul.util.ZuulRuntimeException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import static nl.codebase.faceter.common.FaceterConstants.PARAM_REFRESH_TOKEN;
import static nl.codebase.entities.zuul.ProxyConstants.PARAM_GRANT_TYPE;
import static nl.codebase.entities.zuul.ProxyConstants.STATUS_UNAUTHORIZED;

/**
 * Checks if a refresh token cookie is present when the grant type is refresh_token.
 */
@Slf4j
@Component
public class InvalidRequestFilter extends ZuulFilter {


    @Override
    public String filterType() {
        return "pre";
    }

    @Override
    public int filterOrder() {
        return 0;
    }

    @Override
    public boolean shouldFilter() {
        return true;
    }

    @Override
    public Object run() {

        if(isRefreshTokenCallWithMissingRefreshToken()) {
            throw new ZuulRuntimeException(new ZuulException("No refresh token found",
                    HttpStatus.UNAUTHORIZED.value(), STATUS_UNAUTHORIZED));
        }

        return null;
    }

    private boolean isRefreshTokenCallWithMissingRefreshToken() {
        String grantType = RequestUtil.getParameter(PARAM_GRANT_TYPE);
        if(grantType != null && grantType.equals(PARAM_REFRESH_TOKEN)) {
            String refreshToken = RequestUtil.getCookieValue(PARAM_REFRESH_TOKEN);
            if(refreshToken == null) {
                return true;

            }
        }
        return false;
    }
}
