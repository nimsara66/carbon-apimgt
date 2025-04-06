package org.wso2.carbon.apimgt.gateway.mediators.ai.guardrails;

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
import org.wso2.carbon.apimgt.gateway.APIMgtGatewayConstants;
import org.wso2.carbon.apimgt.gateway.utils.GatewayUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;
import javax.xml.stream.XMLStreamException;

public class JSONKeysGuardrail extends AbstractMediator implements ManagedLifecycle {
    private static final Log logger = LogFactory.getLog(JSONKeysGuardrail.class);

    private String targetKeys;
    private String jsonProperty = "";
    private boolean inverse = false;
    private List<String> keys = new ArrayList<>();

    @Override
    public void init(SynapseEnvironment synapseEnvironment) {
        if (logger.isDebugEnabled()) {
            logger.debug("JSONKeysGuardrail: Initialized.");
        }
    }

    @Override
    public void destroy() {
    }

    @Override
    public boolean mediate(MessageContext messageContext) {
        if (logger.isDebugEnabled()) {
            logger.debug("JSONKeysGuardrail mediator is activated...");
        }

        try {
            boolean containsTargetKeys = hasMatchingJson(messageContext, jsonProperty);
            boolean result = inverse != containsTargetKeys;

            if (!result) {
                GatewayUtils.handleThreat(messageContext, APIMgtGatewayConstants.HTTP_SC_CODE,
                        "Threat detected in request payload: Required JSON keys found.");
            }
        } catch (Exception e) {
            GatewayUtils.handleThreat(messageContext, APIMgtGatewayConstants.HTTP_SC_CODE,
                    "Cannot process the request payload.");
        }

        return true;
    }

    public String getTargetKeys() {
        return targetKeys;
    }

    public void setTargetKeys(String targetKeys) {
        this.targetKeys = targetKeys;
        this.keys = Arrays.stream(targetKeys.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toList());
    }

    public String getJsonProperty() {
        return jsonProperty;
    }

    public void setJsonProperty(String jsonProperty) {
        this.jsonProperty = jsonProperty;
    }

    public boolean getInverse() {
        return inverse;
    }

    public void setInverse(boolean inverse) {
        this.inverse = inverse;
    }

    private boolean hasMatchingJson(MessageContext messageContext, String jsonProperty)
            throws Exception {
        org.apache.axis2.context.MessageContext axis2MC =
                ((Axis2MessageContext) messageContext).getAxis2MessageContext();

        String jsonPayload = JsonUtil.jsonPayloadToString(axis2MC);
        if (jsonPayload == null || jsonPayload.isEmpty()) {
            return false;
        }

        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode rootNode = objectMapper.readTree(jsonPayload);

        if (jsonProperty == null || jsonProperty.trim().isEmpty()) {
            return containsAnyTargetKeys(jsonPayload);
        }

        List<String> values = rootNode.findValuesAsText(jsonProperty);
        return values.stream().anyMatch(this::containsAnyTargetKeys);
    }

    private boolean containsAnyTargetKeys(String input) {
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            Pattern pattern = Pattern.compile("\\{.*?\\}", Pattern.DOTALL);
            Matcher matcher = pattern.matcher(input);

            while (matcher.find()) {
                String candidate = matcher.group(0);
                try {
                    JsonNode node = objectMapper.readTree(candidate);
                    if (node.isObject()) {
                        Iterator<String> fieldNames = node.fieldNames();
                        while (fieldNames.hasNext()) {
                            String key = fieldNames.next();
                            if (keys.contains(key)) {
                                return true;
                            }
                        }
                    }
                } catch (Exception ignore) {
                    // skip malformed JSON
                }
            }
        } catch (Exception e) {
            logger.error("Error while checking JSON keys", e);
        }

        return false;
    }
}
