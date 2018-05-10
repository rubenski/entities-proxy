package nl.codebase.entities.zuul.filter;

import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.http.HttpServletRequestWrapper;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.Optional;

import static nl.codebase.entities.common.FaceterConstants.PARAM_ACCESS_TOKEN;
import static nl.codebase.entities.common.FaceterConstants.PARAM_REFRESH_TOKEN;

public class RequestUtil {

    public static HttpServletRequest getRequest() {
        RequestContext context = RequestContext.getCurrentContext();
        HttpServletRequestWrapper wrapperRequest = (HttpServletRequestWrapper) context.getRequest();
        return wrapperRequest.getRequest();
    }

    public static String getParameter(String param) {
        return getRequest().getParameter(param);
    }

    public static String getCookieValue(String cookie) {
        Cookie[] cookies = getRequest().getCookies();
        if(cookies == null) {
            return null;
        }
        Optional<Cookie> optionalCookie = Arrays.stream(cookies).filter(c -> c.getName().equals(cookie)).findFirst();
        return optionalCookie.isPresent() ? optionalCookie.get().getValue() : null;
    }

    public static String getAccessToken() {
        return getCookieValue(PARAM_ACCESS_TOKEN);
    }

    public static String getRefreshToken() {
        return getCookieValue(PARAM_REFRESH_TOKEN);
    }

    public static boolean hasAccessToken() {
        return getCookieValue(PARAM_ACCESS_TOKEN) != null;
    }

    public static boolean hasRefreshToken() {
        return getCookieValue(PARAM_REFRESH_TOKEN) != null;
    }
}
