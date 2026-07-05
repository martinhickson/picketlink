package org.picketlink.auth.oauth.model;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

public final class TokenRequest {

    private final String grantType;
    private final String scope;
    private final String authorizationHeader;
    private final Map<String, String> formParameters;

    private TokenRequest(Builder builder) {
        this.grantType = builder.grantType;
        this.scope = builder.scope;
        this.authorizationHeader = builder.authorizationHeader;
        this.formParameters = Collections.unmodifiableMap(new LinkedHashMap<>(builder.formParameters));
    }

    public String getGrantType() {
        return grantType;
    }

    public String getScope() {
        return scope;
    }

    public String getAuthorizationHeader() {
        return authorizationHeader;
    }

    public Map<String, String> getFormParameters() {
        return formParameters;
    }

    public String getFormParameter(String name) {
        return formParameters.get(name);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private String grantType;
        private String scope;
        private String authorizationHeader;
        private final Map<String, String> formParameters = new LinkedHashMap<>();

        public Builder grantType(String value) {
            this.grantType = value;
            return this;
        }

        public Builder scope(String value) {
            this.scope = value;
            return this;
        }

        public Builder authorizationHeader(String value) {
            this.authorizationHeader = value;
            return this;
        }

        public Builder formParameter(String name, String value) {
            if (name != null && value != null) {
                formParameters.put(name, value);
            }
            return this;
        }

        public Builder formParameters(Map<String, String> values) {
            Objects.requireNonNull(values, "values");
            formParameters.putAll(values);
            return this;
        }

        public TokenRequest build() {
            return new TokenRequest(this);
        }
    }
}
