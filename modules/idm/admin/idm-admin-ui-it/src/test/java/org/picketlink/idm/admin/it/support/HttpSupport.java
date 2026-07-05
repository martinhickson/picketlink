package org.picketlink.idm.admin.it.support;

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
