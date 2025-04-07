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
import org.wso2.carbon.apimgt.gateway.APIMgtGatewayConstants.AIGuardrailConstants;
import org.wso2.carbon.apimgt.gateway.utils.GatewayUtils;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;

/**
 * A guardrail mediator that can validate JSON payloads against either a JSON schema
 * or check for specific JSON keys. The validation mode is determined by which configuration
 * parameter is set (jsonSchema or targetKeys).
 */
public class BasicGuardrail extends AbstractMediator implements ManagedLifecycle {
    private static final Log logger = LogFactory.getLog(BasicGuardrail.class);

    private String jsonSchema;
    private String targetKeys;
    private String regexString;
    private String wordCountRange;
    private String sentenceCountRange;
    private String jsonProperty = "";
    private boolean doInvert = false;
    private boolean doDeny = true;
    private String decodedJsonSchema;
    private List<String> keys = new ArrayList<>();
    private Pattern regexPattern;
    private int minWordCount;
    private int maxWordCount;
    private int minSentenceCount;
    private int maxSentenceCount;
    private AIGuardrailConstants.GuardrailType guardrailType;

    @Override
    public void init(SynapseEnvironment synapseEnvironment) {
        if (logger.isDebugEnabled()) {
            logger.debug("BasicGuardrail: Initialized.");
        }
    }

    @Override
    public void destroy() {

    }

    /**
     * Mediates the message by validating the JSON payload according to the configured guardrail type.
     *
     * @param messageContext The message context containing the request payload
     * @return Always returns true to continue the message flow
     */
    @Override
    public boolean mediate(MessageContext messageContext) {
        if (logger.isDebugEnabled()) {
            logger.debug("BasicGuardrail mediator is activated...");
        }

        try {
            boolean validationResult = validatePayload(messageContext);
            boolean finalResult = doInvert != validationResult;

            if (!finalResult) {
                String errorMessage;
                String errorCode = messageContext.isResponse()
                        ? AIGuardrailConstants.BAD_RESPONSE
                        : AIGuardrailConstants.BAD_REQUEST;
                switch (guardrailType) {
                    case SCHEMA_VALIDATION:
                        errorMessage = "JSON schema validation failed";
                        break;
                    case KEYS_VALIDATION:
                        errorMessage = "Restricted JSON keys detected";
                        break;
                    case REGEX_VALIDATION:
                        errorMessage = "Regex pattern match detected";
                        break;
                    case WORD_COUNT_VALIDATION:
                        errorMessage = "Word count validation failed";
                        break;
                    case SENTENCE_COUNT_VALIDATION:
                        errorMessage = "Sentence count validation failed";
                        break;
                    default:
                        errorMessage = "Validation failed";
                }

                if (doDeny) {
                    GatewayUtils.handleThreat(messageContext, APIMgtGatewayConstants.HTTP_SC_CODE,
                            "Threat detected in request payload: " + errorMessage);
                } else {
                    prepareAndAttachVerdict(errorMessage, errorCode);
                }
            }
        } catch (Exception e) {
            logger.error("Error processing request payload", e);
            GatewayUtils.handleThreat(messageContext, APIMgtGatewayConstants.HTTP_SC_CODE,
                    "Cannot process the request payload");
        }
        return true;
    }

    /**
     * Validates the payload according to the configured guardrail type.
     *
     * @param messageContext The message context containing the request payload
     * @return true if validation passes, false otherwise
     */
    private boolean validatePayload(MessageContext messageContext) throws Exception {
        switch (guardrailType) {
            case SCHEMA_VALIDATION:
                return validateAgainstSchema(messageContext, jsonProperty);
            case KEYS_VALIDATION:
                return validateJsonKeys(messageContext, jsonProperty);
            case REGEX_VALIDATION:
                return validateRegex(messageContext, jsonProperty);
            case WORD_COUNT_VALIDATION:
                return validateWordCount(messageContext, jsonProperty);
            case SENTENCE_COUNT_VALIDATION:
                return validateSentenceCount(messageContext, jsonProperty);
            default:
                throw new IllegalStateException("Guardrail type not set");
        }
    }

    /**
     * Validates JSON content against the configured JSON schema.
     */
    private boolean validateAgainstSchema(MessageContext messageContext, String propertyPath)
            throws JsonProcessingException {
        String jsonContent = extractJsonContent(messageContext);
        if (jsonContent == null || jsonContent.isEmpty()) {
            return false;
        }

        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode rootNode = objectMapper.readTree(jsonContent);

        if (propertyPath == null || propertyPath.trim().isEmpty()) {
            return validateJsonAgainstSchema(jsonContent);
        }

        List<String> values = rootNode.findValuesAsText(propertyPath);
        return values.stream().anyMatch(this::validateJsonAgainstSchema);
    }

    /**
     * Validates JSON content for presence of specified keys.
     */
    private boolean validateJsonKeys(MessageContext messageContext, String propertyPath)
            throws Exception {
        String jsonContent = extractJsonContent(messageContext);
        if (jsonContent == null || jsonContent.isEmpty()) {
            return false;
        }

        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode rootNode = objectMapper.readTree(jsonContent);

        if (propertyPath == null || propertyPath.trim().isEmpty()) {
            return checkForTargetKeys(jsonContent);
        }

        List<String> values = rootNode.findValuesAsText(propertyPath);
        return values.stream().anyMatch(this::checkForTargetKeys);
    }

    /**
     * Extracts JSON content from the message context.
     */
    private String extractJsonContent(MessageContext messageContext) {
        org.apache.axis2.context.MessageContext axis2MC =
                ((Axis2MessageContext) messageContext).getAxis2MessageContext();
        return JsonUtil.jsonPayloadToString(axis2MC);
    }

    /**
     * Validates a JSON string against the configured schema.
     */
    private boolean validateJsonAgainstSchema(String input) {
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            Pattern pattern = Pattern.compile(AIGuardrailConstants.JSON_CONTENT_REGEX, Pattern.DOTALL);
            Matcher matcher = pattern.matcher(input);

            JSONObject schemaJson = new JSONObject(decodedJsonSchema);
            Schema schema = SchemaLoader.load(schemaJson);

            while (matcher.find()) {
                String candidate = matcher.group(0);
                try {
                    JsonNode node = objectMapper.readTree(candidate);
                    schema.validate(new JSONObject(node.toString()));
                    return true;
                } catch (Exception ignore) {
                    // Continue to next match
                }
            }
        } catch (Exception e) {
            logger.error("Error validating JSON against schema", e);
        }
        return false;
    }

    /**
     * Checks if the JSON content contains any of the target keys.
     */
    private boolean checkForTargetKeys(String input) {
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            Pattern pattern = Pattern.compile(AIGuardrailConstants.JSON_CONTENT_REGEX, Pattern.DOTALL);
            Matcher matcher = pattern.matcher(input);

            while (matcher.find()) {
                String candidate = matcher.group(0);
                try {
                    JsonNode node = objectMapper.readTree(candidate);
                    if (node.isObject() && containsAnyTargetKey(node)) {
                        return true;
                    }
                } catch (Exception ignore) {
                    // Skip malformed JSON
                }
            }
        } catch (Exception e) {
            logger.error("Error checking JSON keys", e);
        }
        return false;
    }

    private boolean containsAnyTargetKey(JsonNode node) {
        Iterator<String> fieldNames = node.fieldNames();
        while (fieldNames.hasNext()) {
            if (keys.contains(fieldNames.next())) {
                return true;
            }
        }
        return false;
    }

    private boolean validateRegex(MessageContext messageContext, String propertyPath)
            throws JsonProcessingException {
        String jsonContent = extractJsonContent(messageContext);
        if (jsonContent == null || jsonContent.isEmpty()) {
            return false;
        }

        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode rootNode = objectMapper.readTree(jsonContent);

        if (propertyPath == null || propertyPath.trim().isEmpty()) {
            return regexPattern.matcher(jsonContent).find();
        }

        List<String> values = rootNode.findValuesAsText(propertyPath);
        return values.stream().anyMatch(value -> regexPattern.matcher(value).find());
    }

    private boolean validateWordCount(MessageContext messageContext, String propertyPath)
            throws JsonProcessingException {
        int totalWords;
        String jsonContent = extractJsonContent(messageContext);
        if (jsonContent == null || jsonContent.isEmpty()) {
            return false;
        }

        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode rootNode = objectMapper.readTree(jsonContent);

        if (propertyPath == null || propertyPath.trim().isEmpty()) {
            totalWords = countWords(jsonContent);
        } else {
            List<String> values = rootNode.findValuesAsText(propertyPath);
            totalWords = values.stream().mapToInt(this::countWords).sum();
        }
        return totalWords >= minWordCount && totalWords <= maxWordCount;
    }

    /**
     * Counts words in the given text.
     */
    private int countWords(String text) {
        if (text == null || text.trim().isEmpty()) {
            return 0;
        }
        String[] words = text.split(AIGuardrailConstants.WORD_SPLIT_REGEX);
        return words.length;
    }

    private boolean validateSentenceCount(MessageContext messageContext, String propertyPath)
            throws JsonProcessingException {
        int totalSentences;
        String jsonContent = extractJsonContent(messageContext);
        if (jsonContent == null || jsonContent.isEmpty()) {
            return false;
        }

        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode rootNode = objectMapper.readTree(jsonContent);

        if (propertyPath == null || propertyPath.trim().isEmpty()) {
            totalSentences = countWords(jsonContent);
        } else {
            List<String> values = rootNode.findValuesAsText(propertyPath);
            totalSentences = values.stream().mapToInt(this::countWords).sum();
        }
        return totalSentences >= minSentenceCount && totalSentences <= maxSentenceCount;
    }

    /**
     * Counts words in the given text.
     */
    private int countSentences(String text) {
        if (text == null || text.trim().isEmpty()) {
            return 0;
        }
        String[] sentences = text.split(AIGuardrailConstants.SENTENCE_SPLIT_REGEX);
        return sentences.length;
    }

    private void prepareAndAttachVerdict(String errorMessage, String errorCode) {
        // TODO: In case of non-blocking attach the verdict to the payload
        // or message context so that another mediator can attach that to the payload
    }

    /**
     * Sets the JSON Schema validation pattern from a Base64 encoded string.
     * The provided string is decoded and stored as a UTF-8 string.
     * Upon setting this value, the guardrail type is automatically set to {@code GuardrailType.SCHEMA_VALIDATION}.
     *
     * @param jsonSchema A Base64 encoded string representing the JSON Schema
     * @throws IllegalArgumentException If the provided string is not a valid Base64 encoded JSON Schema
     */
    public void setJsonSchema(String jsonSchema) {
        this.jsonSchema = jsonSchema;
        byte[] decodedBytes = Base64.getDecoder().decode(jsonSchema);
        this.decodedJsonSchema = new String(decodedBytes, StandardCharsets.UTF_8);
        this.guardrailType = AIGuardrailConstants.GuardrailType.SCHEMA_VALIDATION;
    }

    /**
     * Sets the target keys for validation and processes them into a list.
     * The provided comma-separated string is split, trimmed, and filtered to remove empty entries.
     * Upon setting this value, the guardrail type is automatically set to {@code GuardrailType.KEYS_VALIDATION}.
     *
     * @param targetKeys A comma-separated string of keys to be validated
     */
    public void setTargetKeys(String targetKeys) {
        this.targetKeys = targetKeys;
        this.keys = Arrays.stream(targetKeys.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toList());
        this.guardrailType = AIGuardrailConstants.GuardrailType.KEYS_VALIDATION;
    }

    /**
     * Sets the regular expression (regex) string used for matching or validation.
     * <p>
     * This method also compiles the provided regex string into a {@link Pattern} object
     * and sets the guardrail type to {@code REGEX_VALIDATION}.
     * </p>
     *
     * @param regexString the regex pattern as a {@link String}.
     */
    public void setRegexString(String regexString) {
        this.regexString = regexString;
        this.regexPattern = Pattern.compile(regexString);
        this.guardrailType = AIGuardrailConstants.GuardrailType.REGEX_VALIDATION;
    }

    /**
     * Sets the word count range for validation.
     * <p>
     * The input should be a comma-separated string in the format "min,max",
     * where "min" and "max" are integer values representing the minimum and maximum allowed word counts.
     * This method also parses the range and sets the internal {@code minWordCount} and {@code maxWordCount} fields.
     * Additionally, it sets the {@code guardrailType} to {@code WORD_COUNT_VALIDATION}.
     * </p>
     *
     * @param wordCountRange the word count range string, e.g., "10,100"
     * @throws NumberFormatException if the provided values are not valid integers
     * @throws ArrayIndexOutOfBoundsException if the input does not contain exactly two values
     */
    public void setWordCountRange(String wordCountRange) {
        this.wordCountRange = wordCountRange;
        String[] wordCountLimits = wordCountRange.split(",");
        this.minWordCount = Integer.parseInt(wordCountLimits[0].trim());
        this.maxWordCount = Integer.parseInt(wordCountLimits[1].trim());
        this.guardrailType = AIGuardrailConstants.GuardrailType.WORD_COUNT_VALIDATION;
    }

    /**
     * Sets the sentence count range for validation.
     * <p>
     * The input should be a comma-separated string in the format "min,max",
     * where "min" and "max" are integer values representing the minimum and maximum allowed sentence counts.
     * This method also parses the range and sets the internal {@code minSentenceCount} and {@code maxSentenceCount} fields.
     * Additionally, it sets the {@code guardrailType} to {@code SENTENCE_COUNT_VALIDATION}.
     * </p>
     *
     * @param sentenceCountRange the sentence count range string, e.g., "2,10"
     * @throws NumberFormatException if the provided values are not valid integers
     * @throws ArrayIndexOutOfBoundsException if the input does not contain exactly two values
     */
    public void setSentenceCountRange(String sentenceCountRange) {
        this.sentenceCountRange = sentenceCountRange;
        String[] sentenceCountLimits = sentenceCountRange.split(",");
        this.minSentenceCount = Integer.parseInt(sentenceCountLimits[0].trim());
        this.maxSentenceCount = Integer.parseInt(sentenceCountLimits[1].trim());
        this.guardrailType = AIGuardrailConstants.GuardrailType.SENTENCE_COUNT_VALIDATION;
    }

    /**
     * Sets the JSON property to be used during validation.
     *
     * @param jsonProperty The JSON property
     */
    public void setJsonProperty(String jsonProperty) {
        this.jsonProperty = jsonProperty;
    }

    /**
     * Sets whether the validation logic should be inverted.
     *
     * @param doInvert {@code true} to invert the validation logic, {@code false} otherwise
     */
    public void setDoInvert(boolean doInvert) {
        this.doInvert = doInvert;
    }

    /**
     * Sets whether the guardrail should block requests on validation failure.
     *
     * @param doDeny {@code true} to block requests on validation failure, {@code false} otherwise
     */
    public void setDoDeny(boolean doDeny) {
        this.doDeny = doDeny;
    }

    /**
     * Returns the JSON Schema used for validation.
     *
     * @return The JSON Schema as a string, or {@code null} if not set
     */
    public String getJsonSchema() {
        return jsonSchema;
    }

    /**
     * Returns the original comma-separated string of target keys.
     *
     * @return The target keys as a comma-separated string, or {@code null} if not set
     */
    public String getTargetKeys() {
        return targetKeys;
    }

    /**
     * Retrieves the regular expression (regex) string used for matching or validation.
     *
     * @return the regex pattern as a {@link String}.
     */
    public String getRegexString() {
        return regexString;
    }

    /**
     * Retrieves the configured word count range as a String.
     * <p>
     * The range is typically represented in the format "min,max",
     * where "min" and "max" are integer values defining the lower and upper bounds
     * of the acceptable word count.
     * </p>
     *
     * @return the word count range string, e.g., "10,100"
     */
    public String getWordCountRange() {
        return wordCountRange;
    }

    /**
     * Retrieves the configured sentence count range as a String.
     * <p>
     * The range is typically represented in the format "min,max",
     * where "min" and "max" are integer values defining the lower and upper bounds
     * of the acceptable sentence count.
     * </p>
     *
     * @return the sentence count range string, e.g., "2,10"
     */
    public String getSentenceCountRange() {
        return sentenceCountRange;
    }

    /**
     * Returns the JSON property used for validation.
     *
     * @return The JSON property as a string, or {@code null} if not set
     */
    public String getJsonProperty() {
        return jsonProperty;
    }

    /**
     * Returns whether the validation logic is inverted.
     *
     * @return {@code true} if validation logic is inverted, {@code false} otherwise
     */
    public boolean getDoInvert() {
        return doInvert;
    }

    /**
     * Returns whether the guardrail blocks requests on validation failure.
     *
     * @return {@code true} if requests are blocked on validation failure, {@code false} otherwise
     */
    public boolean getDoDeny() {
        return doDeny;
    }
}