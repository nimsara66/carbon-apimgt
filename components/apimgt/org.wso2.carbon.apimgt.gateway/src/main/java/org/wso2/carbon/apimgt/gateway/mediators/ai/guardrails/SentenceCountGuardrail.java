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

import com.fasterxml.jackson.core.JsonProcessingException;
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

public class SentenceCountGuardrail extends AbstractMediator implements ManagedLifecycle {
    private static final Log logger = LogFactory.getLog(SentenceCountGuardrail.class);
    private int sentenceCount;
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
            int sentenceCountResult = countSentencesInJsonProperty(messageContext, jsonProperty);

            // Evaluate based on 'inverse' flag
            boolean sentenceCheckResult = inverse == (sentenceCountResult <= sentenceCount);

            // If sentence count check fails, handle the threat
            if (!sentenceCheckResult) {
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
    public int getSentenceCount() {

        return sentenceCount;
    }

    /**
     * Sets the failover configuration.
     *
     * @param sentenceCount The failover configuration JSON.
     */
    public void setSentenceCount(int sentenceCount) {

        this.sentenceCount = sentenceCount;
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
    private int countSentencesInJsonProperty(MessageContext messageContext, String jsonProperty)
            throws JsonProcessingException {
        org.apache.axis2.context.MessageContext axis2MC =
                ((Axis2MessageContext) messageContext).getAxis2MessageContext();

        // Get JSON payload as string
        String jsonPayload = JsonUtil.jsonPayloadToString(axis2MC);
        if (jsonPayload == null || jsonPayload.isEmpty()) {
            return 0;
        }

        // Parse JSON
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode rootNode = objectMapper.readTree(jsonPayload);

        // If jsonProperty is null or empty, count sentences in the full payload
        if (jsonProperty == null || jsonProperty.trim().isEmpty()) {
            return countSentences(jsonPayload);
        }

        // Use Jackson's built-in findValuesAsText() to get all values of the given property
        List<String> values = rootNode.findValuesAsText(jsonProperty);

        // Count sentences across all occurrences of the property
        return values.stream().mapToInt(this::countSentences).sum();
    }

    private int countSentences(String text) {
        if (text == null || text.trim().isEmpty()) {
            return 0;
        }
        // Split using regex that detects sentence-ending punctuation
        String[] sentences = text.split("(?<=[.!?]|[.!?][\"')\\]])(?=\\s+[A-Z0-9]|$)");
        return sentences.length;
    }
}
