/*
 *  Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com) All Rights Reserved.
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.apimgt.gateway.mediators;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.mediators.AbstractMediator;
import org.apache.axis2.transport.RequestResponseTransport;

/**
 * This mediator handles WS-Addressing header cleanup.
 * It clears the ReplyTo and FaultTo addressing headers, signals the transport that the
 * response is ready, and marks the response as skipped to ensure proper message flow
 * completion.
 */
public class WSAddressingRemovalMediator extends AbstractMediator {

    private static final Log log = LogFactory.getLog(WSAddressingRemovalMediator.class);

    @Override
    public boolean mediate(MessageContext synCtx) {

        if (log.isDebugEnabled()) {
            log.debug("WSAddressingRemovalMediator is activated for message: " + synCtx.getMessageID());
        }

        try {
            org.apache.axis2.context.MessageContext axis2MsgCtx = ((Axis2MessageContext) synCtx).getAxis2MessageContext();

            // Clear WS-Addressing ReplyTo and FaultTo headers for proper message handling.
            axis2MsgCtx.setReplyTo(null);
            axis2MsgCtx.setFaultTo(null);

            // Signal the underlying transport that the response is ready.
            Object transportControl = axis2MsgCtx.getProperty(RequestResponseTransport.TRANSPORT_CONTROL);
            if (transportControl instanceof RequestResponseTransport) {
                ((RequestResponseTransport) transportControl).signalResponseReady();
            }

            // Mark the response as SKIP to complete the message flow.
            if (axis2MsgCtx.getOperationContext() != null) {
                axis2MsgCtx.getOperationContext().setProperty(org.apache.axis2.Constants.RESPONSE_WRITTEN, "SKIP");
            }
        } catch (Exception e) {
            log.error("Error while processing WS-Addressing headers", e);
        }

        return true;
    }

    @Override
    public boolean isContentAware() {

        return false;
    }
}
