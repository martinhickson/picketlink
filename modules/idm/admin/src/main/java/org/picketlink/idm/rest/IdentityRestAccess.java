package org.picketlink.idm.rest;

/**
 * Authorization hook for the identity REST API: every request must carry an Authorization
 * header this validator accepts. Wire it to the deployment's token mechanism (e.g. the
 * PicketLink auth module's {@code JwtIssuanceManager} via an adapter, or a static
 * service token). Default is deny-all.
 */
public interface IdentityRestAccess {

    boolean isAuthorized(String authorizationHeader);

    /** Static bearer token — simplest corporate-integration mode. */
    final class StaticToken implements IdentityRestAccess {

        private final String token;

        public StaticToken(String token) {
            this.token = token;
        }

        @Override
        public boolean isAuthorized(String authorizationHeader) {
            if (authorizationHeader == null
                    || !authorizationHeader.regionMatches(true, 0, "Bearer ", 0, 7)) {
                return false;
            }
            return java.security.MessageDigest.isEqual(
                    token.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                    authorizationHeader.substring(7).trim()
                            .getBytes(java.nio.charset.StandardCharsets.UTF_8));
        }
    }

    IdentityRestAccess DENY_ALL = new IdentityRestAccess() {
        @Override
        public boolean isAuthorized(String authorizationHeader) {
            return false;
        }
    };
}
