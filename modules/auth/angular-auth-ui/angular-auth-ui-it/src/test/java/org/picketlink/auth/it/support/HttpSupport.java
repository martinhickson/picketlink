package org.picketlink.auth.it.support;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

public final class HttpSupport {

    private HttpSupport() {
    }

    public static int executeStatus(HttpUriRequest request) throws IOException {
        try (CloseableHttpClient client = HttpClients.createDefault();
                CloseableHttpResponse response = client.execute(request)) {
            drain(response.getEntity());
            return response.getStatusLine().getStatusCode();
        }
    }

    public static String executeBody(HttpUriRequest request) throws IOException {
        try (CloseableHttpClient client = HttpClients.createDefault();
                CloseableHttpResponse response = client.execute(request)) {
            return readEntity(response.getEntity());
        }
    }

    public static String readJsonField(String json, String fieldName) {
        String marker = "\"" + fieldName + "\"";
        int fieldIndex = json.indexOf(marker);
        if (fieldIndex < 0) {
            return null;
        }
        int colon = json.indexOf(':', fieldIndex + marker.length());
        if (colon < 0) {
            return null;
        }
        int quoteStart = json.indexOf('"', colon + 1);
        if (quoteStart < 0) {
            return null;
        }
        int quoteEnd = json.indexOf('"', quoteStart + 1);
        if (quoteEnd < 0) {
            return null;
        }
        return json.substring(quoteStart + 1, quoteEnd);
    }

    private static void drain(HttpEntity entity) throws IOException {
        if (entity != null) {
            EntityUtils.consume(entity);
        }
    }

    private static String readEntity(HttpEntity entity) throws IOException {
        if (entity == null) {
            return "";
        }
        return EntityUtils.toString(entity, StandardCharsets.UTF_8);
    }
}
