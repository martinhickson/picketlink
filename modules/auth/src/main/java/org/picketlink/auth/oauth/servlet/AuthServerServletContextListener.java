package org.picketlink.auth.oauth.servlet;

import java.nio.file.Files;
import java.nio.file.Path;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import org.picketlink.auth.oauth.admin.ClientRegistrationService;
import org.picketlink.auth.oauth.auth.ClientCredentialsAuthenticator;
import org.picketlink.auth.oauth.client.ConstantTimeClientSecretMatcher;
import org.picketlink.auth.oauth.client.store.PersistingClientRegistry;
import org.picketlink.auth.oauth.jwt.JwtAccessTokenIssuer;
import org.picketlink.auth.oauth.jwt.JwtSettings;
import org.picketlink.auth.oauth.jwt.JwtSettingsFactory;
import org.picketlink.auth.oauth.service.ClientCredentialsTokenService;
import org.picketlink.auth.oauth.service.JwtClientCredentialsTokenService;
import org.picketlink.common.config.PicketLinkSecurityConfigPaths;

public class AuthServerServletContextListener implements ServletContextListener {

    @Override
    public void contextInitialized(ServletContextEvent event) {
        ServletContext servletContext = event.getServletContext();
        Path clientsFile = resolveClientsFile(servletContext);
        PersistingClientRegistry registry = AuthServletSupport.createDefaultRegistry(clientsFile);
        JwtSettings jwtSettings = JwtSettingsFactory.fromEnvironment();
        ClientCredentialsAuthenticator authenticator =
                new ClientCredentialsAuthenticator(registry, new ConstantTimeClientSecretMatcher());
        JwtAccessTokenIssuer jwtIssuer = new JwtAccessTokenIssuer(jwtSettings);
        JwtClientCredentialsTokenService tokenService =
                new JwtClientCredentialsTokenService(authenticator, jwtIssuer, jwtSettings);
        ClientRegistrationService registrationService =
                AuthServletSupport.createRegistrationService(registry.getStore());

        servletContext.setAttribute(ClientCredentialsTokenService.class.getName(), tokenService);
        servletContext.setAttribute(ClientRegistrationService.class.getName(), registrationService);
        servletContext.setAttribute(JwtSettings.class.getName(), jwtSettings);
    }

    private static Path resolveClientsFile(ServletContext servletContext) {
        String configured = servletContext.getInitParameter(AuthServletSupport.INIT_PARAM_CLIENTS_FILE);
        if (configured == null || configured.isBlank()) {
            configured = System.getProperty(PicketLinkSecurityConfigPaths.AUTH_CLIENTS_FILE_PROPERTY);
        }
        if (configured != null && !configured.isBlank()) {
            return Path.of(configured.trim());
        }
        Path clientsFile = PicketLinkSecurityConfigPaths.defaultAuthClientsFile();
        try {
            Path parent = clientsFile.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
        } catch (java.io.IOException ex) {
            throw new IllegalStateException("Unable to create clients file directory " + clientsFile.getParent(), ex);
        }
        return clientsFile;
    }
}
