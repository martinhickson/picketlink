package org.picketlink.spring;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Maps a PicketLink-issued JWT to a Spring {@link JwtAuthenticationToken}. The {@code scope}
 * claim (space-separated string) becomes {@code SCOPE_} authorities, so applications can write
 * {@code hasAuthority("SCOPE_read")} exactly like with Spring's own resource-server tokens.
 */
public final class PicketLinkJwtAuthenticationConverter
        implements Converter<Jwt, JwtAuthenticationToken> {

    @Override
    public JwtAuthenticationToken convert(Jwt jwt) {
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        Object scopeClaim = jwt.getClaims().get("scope");
        if (scopeClaim != null) {
            for (String scope : String.valueOf(scopeClaim).trim().split("\\s+")) {
                if (!scope.isEmpty()) {
                    authorities.add(new SimpleGrantedAuthority("SCOPE_" + scope));
                }
            }
        }
        return new JwtAuthenticationToken(jwt, authorities);
    }

    /** Authorities granted by a decoded token — handy for tests. */
    public static List<String> authorityNames(JwtAuthenticationToken token) {
        List<String> names = new ArrayList<>();
        for (GrantedAuthority authority : token.getAuthorities()) {
            names.add(authority.getAuthority());
        }
        return names;
    }
}
