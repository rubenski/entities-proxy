package nl.codebase.entities.zuul.filter;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.exception.ZuulException;
import com.netflix.zuul.http.HttpServletRequestWrapper;
import com.netflix.zuul.http.ServletInputStreamWrapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.netflix.zuul.util.ZuulRuntimeException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.util.StreamUtils;
import org.springframework.web.multipart.support.StandardMultipartHttpServletRequest;

import javax.servlet.ServletInputStream;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static nl.codebase.entities.common.FaceterConstants.PARAM_REFRESH_TOKEN;
import static nl.codebase.entities.zuul.ProxyConstants.PARAM_GRANT_TYPE;
import static nl.codebase.entities.zuul.ProxyConstants.STATUS_UNAUTHORIZED;


/**
 * Moves the refresh token coming from a cookie into the request body so it can be processed by
 * Spring security
 */
@Slf4j
@Component
public class RefreshTokenToBodyPreFilter extends ZuulFilter {

    @Override
    public String filterType() {
        return "pre";
    }

    @Override
    public int filterOrder() {
        return 2;
    }

    @Override
    public boolean shouldFilter() {
        HttpServletRequest request = RequestContext.getCurrentContext().getRequest();
        String requestURI = request.getRequestURI();
        return requestURI.contains("token");
    }

    private Optional<StandardMultipartHttpServletRequest> getRequest() {
        RequestContext context = RequestContext.getCurrentContext();
        InputStream stream = (InputStream) context.get("requestEntity");
        if (stream == null) {
            HttpServletRequestWrapper request = (HttpServletRequestWrapper) context.getRequest();
            if (request.getRequest() instanceof StandardMultipartHttpServletRequest) {
                return Optional.of((StandardMultipartHttpServletRequest) request.getRequest());
            }
        }
        return Optional.empty();
    }

    @Override
    public Object run() {

        RequestContext context = RequestContext.getCurrentContext();
        HttpServletRequestWrapper wrapperRequest = (HttpServletRequestWrapper) context.getRequest();
        HttpServletRequest request = wrapperRequest.getRequest();
        String grantType = request.getParameter(PARAM_GRANT_TYPE);

        // If this is a token refresh attempt we need to check for a cookie containing the refresh token
        if(PARAM_REFRESH_TOKEN.equals(grantType)) {
            // get the refresh token from cookie here and set it in the body

            Cookie[] cookies = context.getRequest().getCookies();

            if(cookies == null) {
                return null;
            }

            Optional<Cookie> refreshTokenCookieOptional = Arrays.stream(cookies).filter(cookie -> PARAM_REFRESH_TOKEN.equals(cookie.getName())).findFirst();

            // Actually we already know it is present when ending up here, because the InvalidRequestFilter
            // will stop the request short when no refresh_token is present for a refresh_token request.
            if(!refreshTokenCookieOptional.isPresent()) {
                throw new ZuulRuntimeException(new ZuulException("No refresh token found", HttpStatus.UNAUTHORIZED.value(), STATUS_UNAUTHORIZED));
            }

            Cookie cookie = refreshTokenCookieOptional.get();
            String refreshToken = cookie.getValue();

            try {
                InputStream in = (InputStream) context.get("requestEntity");
                if (in == null) {
                    in = context.getRequest().getInputStream();
                }
                String body = StreamUtils.copyToString(in, Charset.forName("UTF-8"));
                byte[] bytes = body.getBytes("UTF-8");

                bytes = String.format("refresh_token=%s&grant_type=refresh_token", refreshToken).getBytes();

                byte[] finalBytes = bytes;
                context.setRequest(new HttpServletRequestWrapper(context.getRequest()) {
                    @Override
                    public ServletInputStream getInputStream() throws IOException {
                        return new ServletInputStreamWrapper(finalBytes);
                    }

                    @Override
                    public int getContentLength() {
                        return finalBytes.length;
                    }

                    @Override
                    public long getContentLengthLong() {
                        return finalBytes.length;
                    }

                    @Override
                    public String getParameter(String name) {

                        if(name.equals("refresh_token")) {
                            return "hallelujah";
                        }

                        return super.getParameter(name);
                    }

                    @Override
                    public Map getParameterMap() {
                        return super.getParameterMap();
                    }

                    @Override
                    public String[] getParameterValues(String name) {
                        return super.getParameterValues(name);
                    }

                    @Override
                    public HashMap<String, String[]> getParameters() {
                        return super.getParameters();
                    }


                });
            } catch (IOException e) {

            }

        }
        return null;
    }
}
