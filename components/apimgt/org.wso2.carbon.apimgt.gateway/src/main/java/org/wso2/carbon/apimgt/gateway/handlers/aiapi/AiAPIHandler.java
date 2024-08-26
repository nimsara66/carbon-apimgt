package org.wso2.carbon.apimgt.gateway.handlers.aiapi;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.soap.SOAPBody;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.AbstractSynapseHandler;
import org.apache.synapse.MessageContext;
import org.apache.commons.logging.Log;
import org.apache.synapse.commons.json.JsonUtil;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.transport.passthru.util.RelayUtils;
import org.wso2.carbon.apimgt.gateway.handlers.analytics.Constants;

import javax.xml.stream.XMLStreamException;
import java.io.IOException;
import java.util.Iterator;

public class AiAPIHandler extends AbstractSynapseHandler {

    private static final Log log = LogFactory.getLog(AiAPIHandler.class);

    @Override
    public boolean handleRequestInFlow(MessageContext messageContext) {
        log.info("handleRequestInFlow is invoked");
        try {
            RelayUtils.buildMessage(((Axis2MessageContext) messageContext).getAxis2MessageContext());
        } catch (IOException ex) {
            //In case of an exception, it won't be propagated up,and set response size to 0
            log.error("Error occurred while building the message to" +
                    " calculate the response body size", ex);
        } catch (XMLStreamException ex) {
            log.error("Error occurred while building the message to calculate the response" +
                    " body size", ex);
        }

        SOAPEnvelope env = messageContext.getEnvelope();

        if (env != null) {
            SOAPBody soapbody = env.getBody();

            if (soapbody != null) {
                OMElement bodyElement = (OMElement) (soapbody.getChildElements().next());

                if (bodyElement != null) {
                    // Extracting values using the path
                    String model = getValueByPath(bodyElement, "model");

                    // Print the extracted values
                    log.info("Model: " + model);

                    // Add the extracted values to messageContext
                    messageContext.setProperty("aiModel", model);
                }
            }
        }
        return true;
    }

    @Override
    public boolean handleRequestOutFlow(MessageContext messageContext) {
        log.info("handleRequestOutFlow is invoked");
        return true;
    }

    @Override
    public boolean handleResponseInFlow(MessageContext messageContext) {
        log.info("handleResponseInFlow is invoked");
        try {
            RelayUtils.buildMessage(((Axis2MessageContext) messageContext).getAxis2MessageContext());
        } catch (IOException ex) {
            //In case of an exception, it won't be propagated up,and set response size to 0
            log.error("Error occurred while building the message to" +
                    " calculate the response body size", ex);
        } catch (XMLStreamException ex) {
            log.error("Error occurred while building the message to calculate the response" +
                    " body size", ex);
        }

        SOAPEnvelope env = messageContext.getEnvelope();

        if (env != null) {
            SOAPBody soapbody = env.getBody();

            if (soapbody != null) {
                OMElement bodyElement = (OMElement) (soapbody.getChildElements().next());

                if (bodyElement != null) {
                    // Extracting values using the path
                    String promptTokens = getValueByPath(bodyElement, "usage.prompt_tokens");
                    String completionTokens = getValueByPath(bodyElement, "usage.completion_tokens");
                    String totalTokens = getValueByPath(bodyElement, "usage.total_tokens");

                    // Print the extracted values
                    log.info("Prompt Tokens: " + promptTokens);
                    log.info("Completion Tokens: " + completionTokens);
                    log.info("Total Tokens: " + totalTokens);

                    // Add the extracted values to messageContext
                    messageContext.setProperty("promptTokens", promptTokens);
                    messageContext.setProperty("completionTokens", completionTokens);
                    messageContext.setProperty("totalTokens", totalTokens);
                }
            }
        }

        return true;
    }

    @Override
    public boolean handleResponseOutFlow(MessageContext messageContext) {
        log.info("handleResponseOutFlow is invoked");
        return true;
    }

    private static String getValueByPath(OMElement element, String path) {
        String[] parts = path.split("\\.");

        OMElement currentElement = element;
        for (String part : parts) {
            Iterator<?> children = currentElement.getChildrenWithLocalName(part);

            if (children.hasNext()) {
                currentElement = (OMElement) children.next();
            } else {
                // If the part is not found, return null
                return null;
            }
        }

        // Return the text content of the final element
        return currentElement.getText();
    }
}
