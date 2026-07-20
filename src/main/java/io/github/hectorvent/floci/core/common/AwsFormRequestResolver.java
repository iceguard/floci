package io.github.hectorvent.floci.core.common;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.MediaType;
import org.jboss.logging.Logger;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

@ApplicationScoped
public class AwsFormRequestResolver {

    private static final Logger LOG = Logger.getLogger(AwsFormRequestResolver.class);

    public String firstParameter(ContainerRequestContext ctx, String name) {
        String queryValue = ctx.getUriInfo().getQueryParameters().getFirst(name);
        if (queryValue != null) {
            return queryValue;
        }

        MediaType mediaType = ctx.getMediaType();
        if (!isFormEncoded(mediaType)) {
            return null;
        }

        InputStream input = ctx.getEntityStream();
        if (input == null) {
            return null;
        }

        byte[] body;
        try {
            body = input.readAllBytes();
        } catch (IOException e) {
            LOG.debugv(e, "Unable to read form request body while resolving IAM authorization");
            return null;
        }
        ctx.setEntityStream(new ByteArrayInputStream(body));

        Charset charset = resolveCharset(mediaType);
        String form = new String(body, charset);
        for (String pair : form.split("&")) {
            int equals = pair.indexOf('=');
            String key = equals < 0 ? pair : pair.substring(0, equals);
            if (name.equals(URLDecoder.decode(key, charset))) {
                return equals < 0 ? "" : URLDecoder.decode(pair.substring(equals + 1), charset);
            }
        }
        return null;
    }

    private static boolean isFormEncoded(MediaType mediaType) {
        return mediaType != null
                && "application".equalsIgnoreCase(mediaType.getType())
                && "x-www-form-urlencoded".equalsIgnoreCase(mediaType.getSubtype());
    }

    private static Charset resolveCharset(MediaType mediaType) {
        String charsetName = mediaType.getParameters().get("charset");
        if (charsetName == null || charsetName.isBlank()) {
            return StandardCharsets.UTF_8;
        }
        try {
            return Charset.forName(charsetName);
        } catch (RuntimeException e) {
            return StandardCharsets.UTF_8;
        }
    }
}
