package org.wso2.carbon.apimgt.gateway.handlers.aiapi;

public class AiVendorMetadata {
    private final String vendorName;
    private final String aiModelName;

    public AiVendorMetadata(String vendorName, String aiModelName) {
        this.vendorName = vendorName;
        this.aiModelName = aiModelName;
    }

    public String getVendorName() {
        return vendorName;
    }

    public String getAiModelName() {
        return aiModelName;
    }
}
