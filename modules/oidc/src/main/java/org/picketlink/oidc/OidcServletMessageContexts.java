package org.picketlink.oidc;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.cxf.jaxrs.ext.MessageContext;
import org.apache.cxf.jaxrs.ext.MessageContextImpl;
import org.apache.cxf.message.Message;
import org.apache.cxf.message.MessageImpl;
import org.apache.cxf.transport.http.AbstractHTTPDestination;

public final class OidcServletMessageContexts {

    private OidcServletMessageContexts() {
    }

    public static MessageContext from(HttpServletRequest request, HttpServletResponse response) {
        Message message = new MessageImpl();
        message.setContent(HttpServletRequest.class, request);
        message.setContent(HttpServletResponse.class, response);
        message.put(AbstractHTTPDestination.HTTP_REQUEST, request);
        message.put(AbstractHTTPDestination.HTTP_RESPONSE, response);
        return new MessageContextImpl(message);
    }
}
