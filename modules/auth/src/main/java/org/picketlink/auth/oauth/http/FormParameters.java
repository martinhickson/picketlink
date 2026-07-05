package org.picketlink.auth.oauth.http;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

public final class FormParameters {

    private FormParameters() {
    }

    public static Map<String, String> parse(String body) {
        if (body == null || body.isEmpty()) {
            return Collections.emptyMap();
        }

        Map<String, String> parameters = new LinkedHashMap<>();
        for (String pair : body.split("&", -1)) {
            if (pair.isEmpty()) {
                continue;
            }
            int separator = pair.indexOf('=');
            String name = separator >= 0 ? pair.substring(0, separator) : pair;
            String value = separator >= 0 ? pair.substring(separator + 1) : "";
            parameters.put(decode(name), decode(value));
        }
        return parameters;
    }

    private static String decode(String value) {
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException ex) {
            throw new IllegalStateException("UTF-8 is required", ex);
        }
    }
}
