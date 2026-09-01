package org.picketlink.oidc.provider;

import java.io.IOException;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * CORS for browser-based public clients (SPAs using authorization code + PKCE): handles
 * OPTIONS preflights and decorates responses. Origins are allow-listed through the
 * {@code allowedOrigins} init-param (comma-separated) — never {@code *} with credentials.
 */
public final class ProviderCorsFilter implements Filter {

    public static final String INIT_PARAM_ORIGINS = "allowedOrigins";

    private String[] allowedOrigins = new String[0];

    @Override
    public void init(FilterConfig config) {
        String origins = config.getInitParameter(INIT_PARAM_ORIGINS);
        if (origins != null && !origins.isBlank()) {
            allowedOrigins = origins.split(",");
        }
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse,
            FilterChain chain) throws IOException, ServletException {
        if (!(servletRequest instanceof HttpServletRequest)
                || !(servletResponse instanceof HttpServletResponse)) {
            chain.doFilter(servletRequest, servletResponse);
            return;
        }
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;
        String origin = request.getHeader("Origin");
        String allowed = match(origin);
        if (allowed != null) {
            response.setHeader("Access-Control-Allow-Origin", allowed);
            response.setHeader("Access-Control-Allow-Credentials", "true");
            response.setHeader("Access-Control-Allow-Headers",
                    "Authorization, Content-Type, DPoP");
            response.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
            response.setHeader("Vary", "Origin");
        }
        if ("OPTIONS".equalsIgnoreCase(request.getMethod()) && allowed != null) {
            response.setStatus(HttpServletResponse.SC_NO_CONTENT);
            return;
        }
        chain.doFilter(request, response);
    }

    private String match(String origin) {
        if (origin == null) {
            return null;
        }
        for (String allowed : allowedOrigins) {
            if (origin.equals(allowed.trim())) {
                return origin;
            }
        }
        return null;
    }
}
