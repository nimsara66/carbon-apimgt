package org.wso2.carbon.apimgt.gateway.mediators.ai.guardrails;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.re2j.Matcher;
import com.google.re2j.Pattern;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.ManagedLifecycle;
import org.apache.synapse.MessageContext;
import org.apache.synapse.commons.json.JsonUtil;
import org.apache.synapse.core.SynapseEnvironment;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.mediators.AbstractMediator;
import org.everit.json.schema.Schema;
import org.everit.json.schema.loader.SchemaLoader;
import org.json.JSONObject;
import org.wso2.carbon.apimgt.gateway.APIMgtGatewayConstants;
import org.wso2.carbon.apimgt.gateway.utils.GatewayUtils;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class JSONSchemaGuardrail extends AbstractMediator implements ManagedLifecycle {
    private static final Log logger = LogFactory.getLog(JSONSchemaGuardrail.class);
    private String jsonSchema;
    private String jsonProperty = "";
    private boolean inverse = false;
    /**
     * Initializes the AIAPIMediator.
     *
     * @param synapseEnvironment The Synapse environment instance.
     */
    @Override
    public void init(SynapseEnvironment synapseEnvironment) {
        if (log.isDebugEnabled()) {
            log.debug("AIAPIMediator: Initialized.");
        }
    }

    /**
     * Destroys the AIAPIMediator instance and releases any allocated resources.
     */
    @Override
    public void destroy() {

    }

    /**
     * This mediate method gets the message context and validate against the special characters.
     *
     * @param messageContext contains the message properties of the relevant API request which was
     *                       enabled the regexValidator message mediation in flow.
     * @return A boolean value.True if successful and false if not.
     */
    @Override
    public boolean mediate(MessageContext messageContext) {
        if (logger.isDebugEnabled()) {
            logger.debug("RegularExpressionProtector mediator is activated...");
        }

        try {
            // Count the sentences for the given jsonProperty
            boolean isValidJson = hasValidJson(messageContext, jsonProperty);

            // Evaluate based on 'inverse' flag
            boolean validity = inverse != isValidJson;

            // If sentence count check fails, handle the threat
            if (!validity) {
                GatewayUtils.handleThreat(messageContext, APIMgtGatewayConstants.HTTP_SC_CODE,
                        "Threat detected in request payload: Sentence count validation failed.");
            }
        } catch (JsonProcessingException e) {
            GatewayUtils.handleThreat(messageContext, APIMgtGatewayConstants.HTTP_SC_CODE,
                    "Cannot build the payload");
        }
        return true;
    }

    /**
     * Retrieves the regexString configuration as a JSON string.
     *
     * @return The regexString configuration JSON.
     */
    public String getJsonSchema() {

        return jsonSchema;
    }

    /**
     * Sets the failover configuration.
     *
     * @param jsonSchema The failover configuration JSON.
     */
    public void setJsonSchema(String jsonSchema) {
        byte[] decodedBytes = Base64.getDecoder().decode(jsonSchema);
        this.jsonSchema = new String(decodedBytes, StandardCharsets.UTF_8);
    }

    /**
     * Retrieves the regexString configuration as a JSON string.
     *
     * @return The regexString configuration JSON.
     */
    public boolean getInverse() {

        return inverse;
    }

    /**
     * Sets the failover configuration.
     *
     * @param inverse The failover configuration JSON.
     */
    public void setInverse(boolean inverse) {

        this.inverse = inverse;
    }

    /**
     * Retrieves the regexString configuration as a JSON string.
     *
     * @return The regexString configuration JSON.
     */
    public String getJsonProperty() {

        return jsonProperty;
    }

    /**
     * Sets the failover configuration.
     *
     * @param jsonProperty The failover configuration JSON.
     */
    public void setJsonProperty(String jsonProperty) {

        this.jsonProperty = jsonProperty;
    }

    /**
     * This method checks whether the request body contains matching vulnerable key words.
     *
     * @param messageContext contains the message properties of the relevant API request which was
     *                       enabled the regexValidator message mediation in flow.
     */
    private boolean hasValidJson(MessageContext messageContext, String jsonProperty)
            throws JsonProcessingException {
        org.apache.axis2.context.MessageContext axis2MC =
                ((Axis2MessageContext) messageContext).getAxis2MessageContext();

        // Get JSON payload as string
        String jsonPayload = JsonUtil.jsonPayloadToString(axis2MC);
        if (jsonPayload == null || jsonPayload.isEmpty()) {
            return false;
        }

        // Parse JSON
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode rootNode = objectMapper.readTree(jsonPayload);

        // If jsonProperty is null or empty, count sentences in the full payload
        if (jsonProperty == null || jsonProperty.trim().isEmpty()) {
            return hasMatchingJson(jsonPayload);
        }

        // Use Jackson's built-in findValuesAsText() to get all values of the given property
        List<String> values = rootNode.findValuesAsText(jsonProperty);

        // Count sentences across all occurrences of the property
        return values.stream().anyMatch(this::hasMatchingJson);
    }

    private boolean hasMatchingJson(String input) {
        try {
            ObjectMapper objectMapper = new ObjectMapper();

            // Load schema
            JSONObject schemaJson = new JSONObject(jsonSchema);
            Schema schema = SchemaLoader.load(schemaJson);

            // Match outermost (non-greedy) JSON blocks
            Pattern pattern = Pattern.compile("\\{.*?\\}", Pattern.DOTALL);
            Matcher matcher = pattern.matcher(input);

            while (matcher.find()) {
                String candidate = matcher.group(0);
                try {
                    // Parse and validate
                    JsonNode node = objectMapper.readTree(candidate);
                    schema.validate(new JSONObject(node.toString()));
                    return true;
                } catch (Exception ignore) {
                    // Not valid JSON or schema mismatch — continue to next
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return false;
    }
}
