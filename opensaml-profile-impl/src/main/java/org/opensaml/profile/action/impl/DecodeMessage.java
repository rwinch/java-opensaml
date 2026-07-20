/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.opensaml.profile.action.impl;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecoder;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.profile.action.AbstractProfileAction;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;

import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.primitive.LoggerFactory;

/**
 * Action that decodes an incoming request into a {@link MessageContext}.
 * 
 * @event {@link EventIds#PROCEED_EVENT_ID}
 * @event {@link EventIds#UNABLE_TO_DECODE}
 * @event {@link EventIds#INVALID_MESSAGE}
 * 
 * @post If decode succeeds, ProfileRequestContext.getInboundMessageContext() != null
 * @post The injected {@link MessageDecoder} is destroyed.
 */
public class DecodeMessage extends AbstractProfileAction {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(DecodeMessage.class);

    /** The {@link MessageDecoder} instance used to decode the incoming message. */
    @Nonnull private final MessageDecoder decoder;
    
    /** Optional message type to enforce. */
    @Nullable private Class<?> messageType;

    /**
     * Constructor.
     * 
     * @param messageDecoder the {@link MessageDecoder} used for the incoming request
     */
    public DecodeMessage(@Nonnull final MessageDecoder messageDecoder) {
        decoder = Constraint.isNotNull(messageDecoder, "MessageDecoder cannot be null");
    }
    
    /**
     * Set a message type to enforce after decoding.
     * 
     * @param type message type
     * 
     * @since 5.1.0
     */
    public void setMessageType(@Nullable final Class<?> type) {
        checkSetterPreconditions();
        
        messageType = type;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        try {
            log.debug("{} Decoding message using message decoder of type {} for this request", getLogPrefix(),
                    decoder.getClass().getName());
            decoder.decode();
            final MessageContext msgContext = decoder.getMessageContext();
            final Object msg = msgContext != null ? msgContext.getMessage() : null;

            if (msg != null) {
                if (messageType != null && !messageType.isInstance(msg)) {
                    log.warn("{} Message was of incorrect type, expected {}, saw {}", getLogPrefix(), messageType,
                            msg.getClass().getName());
                    ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MESSAGE);
                }
            } else {
                log.warn("{} Decoder did not produce an incoming message?", getLogPrefix());
            }

            profileRequestContext.setInboundMessageContext(msgContext);
        } catch (final MessageDecodingException e) {
            log.error("{} Unable to decode incoming request", getLogPrefix(), e);
            ActionSupport.buildEvent(profileRequestContext, EventIds.UNABLE_TO_DECODE);
        }
    }
    
}