/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.apimgt.gateway.mediators.ai.guardrails;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.re2j.Pattern;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.soap.SOAPBody;
import org.apache.axiom.soap.SOAPEnvelope;
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
import java.util.Iterator;
import java.util.List;
import javax.xml.stream.XMLStreamException;

/**
 * This mediator would protect the backend resources from the threat vulnerabilities by matching the
 * special key words in the request headers, query/path parameters and body.
 */
public class RegularExpressionProtector extends AbstractMediator implements ManagedLifecycle {
    private static final Log logger = LogFactory.getLog(RegularExpressionProtector.class);
    private String regexPattern;
    private String jsonProperty = "";
    private boolean failOnRegexMatch = false;
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
            boolean regexMatchResult = failOnRegexMatch != isRegexMatchBody(messageContext);
            if (!regexMatchResult) {
                GatewayUtils.handleThreat(messageContext, APIMgtGatewayConstants.HTTP_SC_CODE,
                        "Threat detected in request payload");
            }
        } catch (XMLStreamException | IOException e) {
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
    public String getRegexPattern() {

        return regexPattern;
    }

    /**
     * Sets the failover configuration.
     *
     * @param regexPattern The failover configuration JSON.
     */
    public void setRegexPattern(String regexPattern) {

        this.regexPattern = regexPattern;
    }

    /**
     * Retrieves the regexString configuration as a JSON string.
     *
     * @return The regexString configuration JSON.
     */
    public boolean getFailOnRegexMatch() {

        return failOnRegexMatch;
    }

    /**
     * Sets the failover configuration.
     *
     * @param failOnRegexMatch The failover configuration JSON.
     */
    public void setFailOnRegexMatch(boolean failOnRegexMatch) {

        this.failOnRegexMatch = failOnRegexMatch;
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
    private boolean isRegexMatchBody(MessageContext messageContext) throws XMLStreamException, IOException {
        org.apache.axis2.context.MessageContext axis2MC =
                ((Axis2MessageContext) messageContext).getAxis2MessageContext();

        // Get JSON payload as string
        String jsonPayload = JsonUtil.jsonPayloadToString(axis2MC);
        if (jsonPayload == null || jsonPayload.isEmpty()) {
            return false;
        }

        // Compile regex
        Pattern pattern = Pattern.compile(regexPattern);

        // Parse JSON
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode rootNode = objectMapper.readTree(jsonPayload);

        // If jsonProperty is not given, check the whole payload
        if (jsonProperty == null || jsonProperty.trim().isEmpty()) {
            return pattern.matcher(jsonPayload).find();
        }

        // Use Jackson's built-in findValuesAsText() to get all values of the given property
        List<String> values = rootNode.findValuesAsText(jsonProperty);

        // Apply regex on all occurrences of the property
        return values.stream().anyMatch(value -> pattern.matcher(value).find());
    }
}

