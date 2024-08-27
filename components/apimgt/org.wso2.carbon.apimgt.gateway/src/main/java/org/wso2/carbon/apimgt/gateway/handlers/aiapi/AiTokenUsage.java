package org.wso2.carbon.apimgt.gateway.handlers.aiapi;

public class AiTokenUsage {
    private final int totalTokens;
    private final int promptTokens;
    private final int completionTokens;

    public AiTokenUsage(int totalTokens, int promptTokens, int completionTokens) {
        this.totalTokens = totalTokens;
        this.promptTokens = promptTokens;
        this.completionTokens = completionTokens;
    }

    // Getters for each field
    public int getTotalTokens() {
        return totalTokens;
    }

    public int getPromptTokens() {
        return promptTokens;
    }

    public int getCompletionTokens() {
        return completionTokens;
    }
}
