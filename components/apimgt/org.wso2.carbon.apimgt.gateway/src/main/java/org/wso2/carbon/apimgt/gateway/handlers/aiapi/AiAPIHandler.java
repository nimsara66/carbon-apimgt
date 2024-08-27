package org.wso2.carbon.apimgt.gateway.handlers.aiapi;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.xpath.AXIOMXPath;
import org.apache.axiom.soap.SOAPBody;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.MessageContext;
import org.apache.commons.logging.Log;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.transport.passthru.util.RelayUtils;

import javax.xml.stream.XMLStreamException;

import org.jaxen.JaxenException;
import org.jaxen.XPath;
import java.io.IOException;
import java.util.Iterator;
import java.util.List;

public class AiAPIHandler extends AbstractAiAPIHandler {

    private static final Log log = LogFactory.getLog(AiAPIHandler.class);

    @Override
    public boolean handleRequestInFlow(MessageContext messageContext) {
        log.info("handleRequestInFlow is invoked");
        // TODO: Check if AI API
        // Or check in the xml.j2
        AiVendorMetadata aiVendorMetadata = getAiVendorMetadata(messageContext);
        messageContext.setProperty("aiVendorMetadata", aiVendorMetadata);

        return true;
    }

    @Override
    public boolean handleRequestOutFlow(MessageContext messageContext) {
        log.info("handleRequestOutFlow is invoked");
        return true;
    }

    @Override
    public boolean handleResponseInFlow(MessageContext messageContext) {
        // TODO: Check if AI API
        // Or check in the xml.j2
        log.info("handleResponseInFlow is invoked");
        AiTokenUsage aiTokenUsage = getAiTokenUsage(messageContext);
        messageContext.setProperty("aiTokenUsage", aiTokenUsage);
        return true;
    }

    @Override
    public boolean handleResponseOutFlow(MessageContext messageContext) {
        log.info("handleResponseOutFlow is invoked");
        return true;
    }

    private String getValueByPath(OMElement element, String path) {
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

    private String getValueByTagName(OMElement element, String tagName) {
        // Create an XPath expression to find the element by tag name
        try {
            XPath xpath = new AXIOMXPath("//" + tagName);
            List<?> result = xpath.selectNodes(element);

            if (!result.isEmpty()) {
                OMElement foundElement = (OMElement) result.get(0);
                return foundElement.getText();  // Return the text content of the found element
            }
        } catch (JaxenException e) {
            log.error("Error while evaluating XPath expression in AiAPIHandler", e);
        }

        return "";
    }

    @Override
    public AiVendorMetadata getAiVendorMetadata(MessageContext messageContext) {
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
                    String model = getValueByTagName(bodyElement, "model");

                    log.info("Model: " + model);

                    // TODO: Get vendor name from dto
                    return new AiVendorMetadata("openai", model);
                }
            }
        }
        return null;
    }

    @Override
    public AiTokenUsage getAiTokenUsage(MessageContext messageContext) {
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
                    String promptTokens = getValueByTagName(bodyElement, "prompt_tokens");
                    String completionTokens = getValueByTagName(bodyElement, "completion_tokens");
                    String totalTokens = getValueByTagName(bodyElement, "total_tokens");

                    // Print the extracted values
                    log.info("Prompt Tokens: " + promptTokens);
                    log.info("Completion Tokens: " + completionTokens);
                    log.info("Total Tokens: " + totalTokens);

                    return new AiTokenUsage(Integer.parseInt(promptTokens), Integer.parseInt(completionTokens), Integer.parseInt(totalTokens));
                }
            }
        }
        return null;
    }
}
