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

package org.opensaml.messaging.decoder;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.messaging.context.MessageContext;
import org.slf4j.Logger;

import net.shibboleth.shared.component.AbstractInitializableComponent;
import net.shibboleth.shared.component.UnmodifiableComponent;
import net.shibboleth.shared.primitive.LoggerFactory;
import net.shibboleth.shared.primitive.StringSupport;

/**
 * Abstract message decoder.
 */
public abstract class AbstractMessageDecoder extends AbstractInitializableComponent
        implements MessageDecoder, UnmodifiableComponent {
    
    /** Logging category for protocol messages. */
    @Nonnull public static final String BASE_PROTOCOL_MESSAGE_LOGGER_CATEGORY = "PROTOCOL_MESSAGE";
    
    /** Used to log protocol messages. */
    @Nonnull private Logger protocolMessageLog = LoggerFactory.getLogger(BASE_PROTOCOL_MESSAGE_LOGGER_CATEGORY);

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(AbstractMessageDecoder.class);

    /** Message context. */
    @Nullable private MessageContext messageContext;
    
    /** The configured logging sub-category for protocol messages. */
    @Nullable private String protocolMessageLoggerSubCategory;

    /** {@inheritDoc} */
    @Nullable public MessageContext getMessageContext() {
        return messageContext;
    }
    
    /**
     * Set the message context.
     * 
     * @param context the message context
     */
    protected void setMessageContext(@Nullable final MessageContext context) {
        messageContext = context;
    }

    /** {@inheritDoc} */
    public void decode() throws MessageDecodingException {
        checkComponentActive();
        doDecode();
        logDecodedMessage();
    }
    
    /**
     * Get the protocol message logger.
     * 
     * @return The protocol message logger
     */
    @Nonnull protected Logger getProtocolMessageLogger() {
        return protocolMessageLog;
    }
    
    /**
     * Get the configured logging sub-category for protocol messages.
     * 
     * @return the logging sub-category
     */
    @Nullable protected String getProtocolMessageLoggerSubCategory() {
        return protocolMessageLoggerSubCategory;
    }
    
    /**
     * Set the configured logging sub-category for protocol messages.
     * 
     * @param category the logging sub-category
     */
    protected void setProtocolMessageLoggerSubCategory(@Nullable final String category) {
        protocolMessageLoggerSubCategory = StringSupport.trimOrNull(category);
        if (protocolMessageLoggerSubCategory != null) {
            protocolMessageLog = LoggerFactory.getLogger(BASE_PROTOCOL_MESSAGE_LOGGER_CATEGORY + "."
                    + protocolMessageLoggerSubCategory);
        } else {
            protocolMessageLog = LoggerFactory.getLogger(BASE_PROTOCOL_MESSAGE_LOGGER_CATEGORY);
        }
    }
    
    /**
     * Log the decoded message to the protocol message logger.
     */
    protected void logDecodedMessage() {
        if (protocolMessageLog.isDebugEnabled() ){
            final String serializedMessage = serializeMessageForLogging(getMessageToLog());
            if (serializedMessage == null) {
                log.debug("Serialized decoded protocol message was null, nothing to log");
                return;
            }
            
            protocolMessageLog.debug("\n" + serializedMessage);
        }
    }
    
    /**
     * Get the XMLObject which will be logged as the protocol message.
     * 
     * @return the XMLObject message considered to be the protocol message for logging purposes
     */
    @Nullable protected Object getMessageToLog() {
        final MessageContext mc = getMessageContext();
        return mc != null ? mc.getMessage() : null;
    }
    
    /**
     * Serialize the message for logging purposes.
     * 
     * <p>
     * Default implementation is to return the message object's {@link #toString()},
     * but subclasses should override if a better message-specific serialization mechanism exists.
     * </p>
     * 
     * @param message the message to serialize
     * 
     * @return the serialized message, or null if message can not be serialized
     */
    @Nullable protected String serializeMessageForLogging(@Nullable final Object message) {
        return message != null ? message.toString() : null;
    }

    /**
     * Performs the decoding logic. By the time this is called, this decoder has already been initialized and checked to
     * ensure that it has not been destroyed.
     * 
     * @throws MessageDecodingException thrown if there is a problem decoding the message
     */
    protected abstract void doDecode() throws MessageDecodingException;
    
    /** {@inheritDoc} */
    @Override
    protected void doDestroy() {
        //
        // Do not call parent destroy to suppress deprecation logging
        //
    }

}