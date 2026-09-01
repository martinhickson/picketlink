package org.picketlink.auth.oauth.issuance;

import org.picketlink.auth.oauth.OAuthConstants;
import org.picketlink.auth.oauth.OAuthException;
import org.picketlink.auth.oauth.model.OAuthErrorResponse;

/** Thrown when an issuance policy rule rejects or cannot accommodate a token request. */
public class IssuancePolicyException extends OAuthException {

    private static final long serialVersionUID = 1L;

    private final String description;

    public IssuancePolicyException(String description) {
        super(new OAuthErrorResponse(OAuthConstants.INVALID_REQUEST, description), 400);
        this.description = description;
    }

    /** Human-readable rejection reason; {@link #getError()} carries the OAuth error code. */
    @Override
    public String getMessage() {
        return description;
    }
}
