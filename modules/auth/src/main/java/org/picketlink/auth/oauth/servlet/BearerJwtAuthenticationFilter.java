package org.picketlink.auth.oauth.servlet;

import java.io.IOException;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.picketlink.auth.oauth.jwt.JwtAccessTokenValidator;
import org.picketlink.auth.oauth.jwt.JwtClaims;
import org.picketlink.auth.oauth.jwt.JwtSettings;
import org.picketlink.auth.oauth.jwt.JwtSettingsFactory;
import org.picketlink.auth.oauth.jwt.JwtValidationException;

public class BearerJwtAuthenticationFilter implements Filter {

    private JwtAccessTokenValidator validator;

    @Override
    public void init(FilterConfig filterConfig) {
        JwtSettings settings = resolveSettings(filterConfig);
        validator = new JwtAccessTokenValidator(settings);
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        String authorization = httpRequest.getHeader("Authorization");
        if (authorization == null || !authorization.regionMatches(true, 0, "Bearer ", 0, 7)) {
            httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Bearer token required");
            return;
        }
        String token = authorization.substring(7).trim();
        try {
            JwtClaims claims = validator.validate(token);
            httpRequest.setAttribute(JwtClaims.class.getName(), claims);
            chain.doFilter(request, response);
        } catch (JwtValidationException ex) {
            httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, ex.getMessage());
        }
    }

    private static JwtSettings resolveSettings(FilterConfig filterConfig) {
        Object configured = filterConfig.getServletContext().getAttribute(JwtSettings.class.getName());
        if (configured instanceof JwtSettings) {
            return (JwtSettings) configured;
        }
        return JwtSettingsFactory.fromEnvironment();
    }
}
