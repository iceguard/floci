package io.github.hectorvent.floci.core.common;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;
import org.jboss.logging.Logger;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

@ApplicationScoped
public class AwsJsonRequestResolver {

    private static final Logger LOG = Logger.getLogger(AwsJsonRequestResolver.class);

    private final ObjectMapper objectMapper;

    @Inject
    public AwsJsonRequestResolver(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public JsonNode body(ContainerRequestContext ctx) {
        InputStream input = ctx.getEntityStream();
        if (input == null) {
            return null;
        }

        byte[] body;
        try {
            body = input.readAllBytes();
        } catch (IOException e) {
            LOG.debugv(e, "Unable to read JSON request body while resolving IAM authorization");
            return null;
        }
        ctx.setEntityStream(new ByteArrayInputStream(body));
        if (body.length == 0) {
            return null;
        }

        try {
            return objectMapper.readTree(body);
        } catch (IOException e) {
            LOG.debugv(e, "Unable to parse JSON request body while resolving IAM authorization");
            return null;
        }
    }

    public String firstTextField(ContainerRequestContext ctx, String fieldName) {
        JsonNode request = body(ctx);
        if (request == null) {
            return null;
        }
        JsonNode value = request.path(fieldName);
        return value.isTextual() ? value.asText() : null;
    }
}
