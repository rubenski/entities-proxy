package nl.codebase.entities.zuul.filter;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.exception.ZuulException;
import nl.codebase.faceter.common.token.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.netflix.zuul.util.ZuulRuntimeException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import static nl.codebase.entities.zuul.ProxyConstants.STATUS_UNAUTHORIZED;

/**
 * Checks if the refresh or access token provided is in the f_logged_out_token table. If so, the request is blocked.
 * A client should never have a token that was logged out. Note that we don't check whether the URL that is accessed
 * is even a protected resource. We just block every request.
 */
@Component
public class LoggedOutTokenBlockerFilter extends ZuulFilter {

    private TokenService tokenService;

    @Autowired
    public LoggedOutTokenBlockerFilter(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @Override
    public String filterType() {
        return "pre";
    }

    @Override
    public int filterOrder() {
        return 1;
    }

    @Override
    public boolean shouldFilter() {
        // Check if either token is present
        return RequestUtil.hasAccessToken() || RequestUtil.hasRefreshToken();
    }

    @Override
    public Object run() {

        if(RequestUtil.hasAccessToken()) {
            if(tokenService.isLoggedOutToken(RequestUtil.getAccessToken())) {
                throw new ZuulRuntimeException(new ZuulException("Access token was logged out", HttpStatus.UNAUTHORIZED.value(), STATUS_UNAUTHORIZED));
            }
        }

        if(RequestUtil.hasRefreshToken()) {
            if(tokenService.isLoggedOutToken(RequestUtil.getRefreshToken())) {
                throw new ZuulRuntimeException(new ZuulException("Refresh token was logged out", HttpStatus.UNAUTHORIZED.value(), STATUS_UNAUTHORIZED));
            }
        }

        return null;
    }
}
