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

package org.opensaml.saml.common.binding;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Base64;
import java.util.Set;
import java.util.stream.Collectors;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.messaging.MessageException;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.common.messaging.context.SAMLBindingContext;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLMessageReceivedEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.saml1.core.ResponseAbstractType;
import org.opensaml.saml.saml2.core.StatusResponseType;
import org.opensaml.saml.saml2.metadata.Endpoint;
import org.slf4j.Logger;

import com.google.common.base.Strings;

import jakarta.servlet.http.HttpServletRequest;
import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.collection.CollectionSupport;
import net.shibboleth.shared.io.NoWrapAutoEndInflaterInputStream;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.primitive.LoggerFactory;
import net.shibboleth.shared.primitive.StringSupport;

/** A support class for SAML binding operations. */
public final class SAMLBindingSupport {
    
    /** Logger. */
    @Nonnull private static final Logger LOG = LoggerFactory.getLogger(SAMLBindingSupport.class);

    /** Constructor. */
    private SAMLBindingSupport() {
        
    }
    
    /**
     * Get the SAML protocol relay state from a message context.
     * 
     * @param messageContext the message context on which to operate
     * @return the relay state or null
     */
    @Nullable @NotEmpty public static String getRelayState(@Nonnull final MessageContext messageContext) {
        final SAMLBindingContext bindingContext = messageContext.getSubcontext(SAMLBindingContext.class);
        if (bindingContext == null) { 
            return null;
        }
        return bindingContext.getRelayState();
    }
    
    /**
     * Set the SAML protocol relay state on a message context.
     * 
     * @param messageContext the message context on which to operate
     * @param relayState the relay state to set
     */
    public static void setRelayState(@Nonnull final MessageContext messageContext, 
            @Nullable final String relayState) {
        messageContext.ensureSubcontext(SAMLBindingContext.class).setRelayState(relayState);
    }
    
    /**
     * Checks that the relay state is 80 bytes or less if it is not null.
     * 
     * @param relayState relay state to check
     * 
     * @return true if the relay state is not empty and is less than 80 bytes
     */
    public static boolean checkRelayState(@Nullable final String relayState) {
        if (!Strings.isNullOrEmpty(relayState)) {
            assert relayState != null;
            if (relayState.getBytes().length > 80) {
                LOG.warn("Relay state exceeds 80 bytes: {}", relayState);
            }

            return true;
        }

        return false;
    }
    
    /**
     * Get the response URL from the relying party endpoint. If the SAML message is a 
     * response and the relying party endpoint contains a response location 
     * then that location is returned otherwise the normal endpoint location is returned.
     * 
     * <p>Instead of raising an exception, this variant returns null in the event of an
     * inability to identify a URL to return.</p>
     * 
     * @param messageContext current message context
     * 
     * @return response URL from the relying party endpoint or null
     * 
     * @since 5.2.0
     */
    @Nullable public static URI getEndpointURLOrNull(@Nonnull final MessageContext messageContext) {
        try {
            return getEndpointURL(messageContext);
        } catch (final BindingException e) {
            return null;
        }
    }
    
    /**
     * Get the response URL from the relying party endpoint. If the SAML message is a 
     * response and the relying party endpoint contains a response location 
     * then that location is returned otherwise the normal endpoint location is returned.
     * 
     * @param messageContext current message context
     * 
     * @return response URL from the relying party endpoint
     * 
     * @throws BindingException throw if no relying party endpoint is available
     */
    @Nonnull public static URI getEndpointURL(@Nonnull final MessageContext messageContext) 
            throws BindingException {
        final SAMLPeerEntityContext peerContext = messageContext.getSubcontext(SAMLPeerEntityContext.class);
        if (peerContext == null) {
            throw new BindingException("Message context contained no PeerEntityContext");
        }
        
        final SAMLEndpointContext endpointContext = peerContext.getSubcontext(SAMLEndpointContext.class);
        if (endpointContext == null) {
            throw new BindingException("PeerEntityContext contained no SAMLEndpointContext");
        }
        
        final Endpoint endpoint = endpointContext.getEndpoint();
        if (endpoint == null) {
            throw new BindingException("Endpoint for relying party was null.");
        }

        final Object message = messageContext.getMessage();
        if ((message instanceof org.opensaml.saml.saml2.core.StatusResponseType 
                || message instanceof org.opensaml.saml.saml1.core.Response) 
                && !Strings.isNullOrEmpty(endpoint.getResponseLocation())) {
            try {
                return new URI(endpoint.getResponseLocation());
            } catch (final URISyntaxException e) {
                throw new BindingException("The endpoint response location " + endpoint.getResponseLocation()
                        + " is not a valid URL", e);
            }
        }
        
        if (Strings.isNullOrEmpty(endpoint.getLocation())) {
            throw new BindingException("Relying party endpoint location was null or empty.");
        }
        try {
            return new URI(endpoint.getLocation());
        } catch (final URISyntaxException e) {
            throw new BindingException("The endpoint location " + endpoint.getLocation()
                    + " is not a valid URL", e);
        }
    }
    
    /**
     * Sets the destination attribute on the outbound message if it is a 
     * {@link org.opensaml.saml.saml1.core.ResponseAbstractType} message.
     * 
     * @param outboundMessage outbound SAML message
     * @param endpointURL destination endpoint
     */
    public static void setSAML1ResponseRecipient(@Nonnull final SAMLObject outboundMessage, 
            @Nonnull @NotEmpty final String endpointURL) {
        if (outboundMessage instanceof org.opensaml.saml.saml1.core.ResponseAbstractType) {
            ((org.opensaml.saml.saml1.core.ResponseAbstractType) outboundMessage).setRecipient(endpointURL);
        }
    }
    
    /**
     * Sets the destination attribute on an outbound message if it is either a 
     * {@link org.opensaml.saml.saml2.core.RequestAbstractType} or a 
     * {@link org.opensaml.saml.saml2.core.StatusResponseType} message.
     * 
     * @param outboundMessage outbound SAML message
     * @param endpointURL destination endpoint
     */
    public static void setSAML2Destination(@Nonnull final SAMLObject outboundMessage, 
            @Nonnull @NotEmpty final String endpointURL) {
        if (outboundMessage instanceof org.opensaml.saml.saml2.core.RequestAbstractType) {
            ((org.opensaml.saml.saml2.core.RequestAbstractType) outboundMessage).setDestination(endpointURL);
        } else if (outboundMessage instanceof org.opensaml.saml.saml2.core.StatusResponseType) {
            ((org.opensaml.saml.saml2.core.StatusResponseType) outboundMessage).setDestination(endpointURL);
        }
    }
    
    /**
     * Determine whether the SAML message represented by the message context is digitally signed.
     * 
     * <p>
     * First the SAML protocol message is examined as to whether an XML signature is present
     * at the DOM level; if yes return true.
     * Finally, the presence of a binding signature is evaluated by looking at 
     * {@link SAMLBindingContext#hasBindingSignature()}.
     * </p>
     * 
     * @param messageContext current message context
     * @return true if the message is considered to be digitally signed, false otherwise
     */
    public static boolean isMessageSigned(@Nonnull final MessageContext messageContext) {
        return isMessageSigned(messageContext, false);
    }
    
    /**
     * Determine whether the SAML message represented by the message context is digitally signed.
     * 
     * <p>
     * First the SAML protocol message is examined as to whether an XML signature is present
     * at the DOM level; if yes return true.
     * Next if <code>presenceSatisfies</code> is true, then {@link SignableSAMLObject#getSignature()}
     * is evaluated for a non-null value; if yes return true.
     * Finally, the presence of a binding signature is evaluated by looking at 
     * {@link SAMLBindingContext#hasBindingSignature()}.
     * </p>
     * 
     * @param messageContext current message context
     * @param presenceSatisfies whether the presence of a non-null {@link org.opensaml.xmlsec.signature.Signature}
     *        member satisfies the evaluation
     * @return true if the message is considered to be digitally signed, false otherwise
     */
    public static boolean isMessageSigned(@Nonnull final MessageContext messageContext,
            final boolean presenceSatisfies) {
        final Object samlMessage = Constraint.isNotNull(messageContext.getMessage(),
                "SAML message was not present in message context");
        if (samlMessage instanceof SignableSAMLObject) {
            final SignableSAMLObject signable = (SignableSAMLObject) samlMessage;
            if (presenceSatisfies && signable.getSignature() != null) {
                return true;
            }
            if (signable.isSigned()) {
                return true;
            }
        }
        
        final SAMLBindingContext bindingContext = messageContext.getSubcontext(SAMLBindingContext.class);
        if (bindingContext != null) {
            return bindingContext.hasBindingSignature();
        }
        return false;
    }

    /**
     * Determine whether the SAML binding to be used by the message context supports signatures
     * at the binding layer.
     * 
     * <p>
     * The capability of the binding is determined by extracting a {@link BindingDescriptor} from a
     * {@link SAMLBindingContext}.
     * </p>
     * 
     * @param messageContext current message context
     * @return true if the message is considered to be digitally signed, false otherwise
     */
    public static boolean isSigningCapableBinding(@Nonnull final MessageContext messageContext) {
        final SAMLBindingContext bindingContext = messageContext.getSubcontext(SAMLBindingContext.class);
        if (bindingContext != null) {
            final BindingDescriptor bd = bindingContext.getBindingDescriptor();
            if (bd != null) {
                return bd.isSignatureCapable();
            }
        }
        return false;
    }

    /**
     * Determine whether the binding in use requires the presence within the message 
     * of information indicating the intended message destination endpoint URI.
     * 
     * @param messageContext current SAML message context
     * @return true if the intended message destination endpoint is required, false if not
     */
    public static boolean isIntendedDestinationEndpointURIRequired(
            @Nonnull final MessageContext messageContext) {
        final SAMLBindingContext bindingContext = messageContext.getSubcontext(SAMLBindingContext.class);
        if (bindingContext == null) {
            return false;
        }
        return bindingContext.isIntendedDestinationEndpointURIRequired();
    }
    
    /**
     * Extract the message information which indicates to what receiver endpoint URI the
     * SAML message was intended to be delivered.
     * 
     * @param messageContext the SAML message context being processed
     * @return the value of the intended destination endpoint URI, or null if not present or empty
     * @throws MessageException thrown if the message is not an instance of SAML message that
     *              could be processed by the decoder
     */
    @Nullable public static String getIntendedDestinationEndpointURI(
            @Nonnull final MessageContext messageContext)  throws MessageException {
        final Object samlMessage = Constraint.isNotNull(messageContext.getMessage(), 
                "SAML message was not present in message context");
        String messageDestination = null;
        //SAML 2 Request
        if (samlMessage instanceof org.opensaml.saml.saml2.core.RequestAbstractType) {
            final org.opensaml.saml.saml2.core.RequestAbstractType request =  
                    (org.opensaml.saml.saml2.core.RequestAbstractType) samlMessage;
            messageDestination = StringSupport.trimOrNull(request.getDestination());
        //SAML 2 Response
        } else if (samlMessage instanceof org.opensaml.saml.saml2.core.StatusResponseType) {
            final org.opensaml.saml.saml2.core.StatusResponseType response = 
                    (org.opensaml.saml.saml2.core.StatusResponseType) samlMessage;
            messageDestination = StringSupport.trimOrNull(response.getDestination());
        //SAML 1 Response
        } else if (samlMessage instanceof org.opensaml.saml.saml1.core.ResponseAbstractType) {
            final org.opensaml.saml.saml1.core.ResponseAbstractType response = 
                    (org.opensaml.saml.saml1.core.ResponseAbstractType) samlMessage;
            messageDestination = StringSupport.trimOrNull(response.getRecipient());
        //SAML 1 Request
        } else if (samlMessage instanceof org.opensaml.saml.saml1.core.RequestAbstractType) {
            // don't treat as an error, just return null
            return null;
        } else if (samlMessage instanceof XMLObject) {
            LOG.error("Unknown XML message type encountered: {}",
                    ((XMLObject) samlMessage).getElementQName().toString());
            throw new MessageException("Invalid XML message type encountered");
        } else {
            LOG.error("Unknown message type encountered");
            throw new MessageException("Invalid message type encountered");
        }
        return messageDestination;
        
    }
    
    /**
     * Extract the transport endpoint URI at which this message was received.
     * 
     * @param messageContext current message context
     * @param request the HttpServletRequest being evaluated
     * @return string representing the transport endpoint URI at which the current message was received
     * @throws MessageException thrown if the endpoint can not be looked up from the message
     *                              context and converted to a string representation
     */
    @Nonnull public static String getActualReceiverEndpointURI(@Nonnull final MessageContext messageContext,
            @Nonnull final HttpServletRequest request) throws MessageException {
        Constraint.isNotNull(request, "HttpServletRequest cannot be null");
        
        final SAMLMessageReceivedEndpointContext receivedEnpointContext =
                messageContext.getSubcontext(SAMLMessageReceivedEndpointContext.class);
        if (receivedEnpointContext != null) {
            final String url = receivedEnpointContext.getRequestURL();
            if (url != null) {
                return url;
            }
        }

        return request.getRequestURL().toString();
    }
    
    /**
     * Extract the transport endpoint URI at which this message was received.
     * 
     * @param messageContext current message context
     * @return string representing the transport endpoint URI at which the current message was received
     * @throws MessageException thrown if the endpoint can not be looked up from the message
     *                              context and converted to a string representation
     *                              
     * @since 5.2.0
     */
    @Nullable public static String getActualReceiverEndpointURI(@Nonnull final MessageContext messageContext)
            throws MessageException {

        final SAMLMessageReceivedEndpointContext receivedEnpointContext =
                messageContext.getSubcontext(SAMLMessageReceivedEndpointContext.class);
        if (receivedEnpointContext != null) {
            final String url = receivedEnpointContext.getRequestURL();
            if (url != null) {
                return url;
            }
        }
        return null;
    }
    
    /**
     * Convert a 2-byte artifact endpoint index byte[] as typically used by SAML 2 artifact types to an integer,
     * appropriate for use with {@link org.opensaml.saml.saml2.metadata.IndexedEndpoint} impls.
     * 
     * <p>
     * The max input value supported is 0x7FFF (32767), which is the largest possible unsigned 16 bit value.
     * This should be more than sufficient for typical SAML cases.
     * </p>
     * 
     * @param artifactEndpointIndex the endpoint index byte array, must have length == 2, and big endian byte order.
     * @return the convert integer value
     */
    public static int convertSAML2ArtifactEndpointIndex(@Nonnull final byte[] artifactEndpointIndex) {
        Constraint.isNotNull(artifactEndpointIndex, "Artifact endpoint index cannot be null");
        Constraint.isTrue(artifactEndpointIndex.length == 2, "Artifact endpoint index length was not 2, was: "
                + artifactEndpointIndex.length);
        final short value = ByteBuffer.wrap(artifactEndpointIndex).order(ByteOrder.BIG_ENDIAN).getShort();
        return Constraint.isGreaterThanOrEqual(0, value, 
                "Input value was too large, resulting in a negative 16-bit short");
    }
    
    /**
     * Evaluate a SAML 1 message {@link SAMLObject} as to whether it is the expected message type (request vs response).
     * 
     * @param expectRequest true if a SAML 1 request is expected (an instance of
     *                      {@link org.opensaml.saml.saml1.core.RequestAbstractType},
     *                      false if a SAML 1 response is expected (an instance of
     *                      {@link org.opensaml.saml.saml1.core.ResponseAbstractType}
     * @param message the message to evaluate
     * 
     * @throws MessageDecodingException  if the message being evaluated is not the expected type
     */
    public static void checkSAML1MessageType(final boolean expectRequest, @Nonnull final SAMLObject message)
            throws MessageDecodingException {
        Constraint.isNotNull(message, "SAML 1 message cannot be null");

        if (expectRequest) {
            if (! org.opensaml.saml.saml1.core.RequestAbstractType.class.isInstance(message)) {
                throw new MessageDecodingException("Expected a SAML 1 request message, but saw: " 
                        + message.getClass().getName());
            }
        } else { 
            if (! ResponseAbstractType.class.isInstance(message)){ 
                throw new MessageDecodingException("Expected a SAML 1 response message, but saw: " 
                        + message.getClass().getName());
            }
        }
    }

    /**
     * Evaluate a SAML 2 message {@link SAMLObject} as to whether it is the expected message type (request vs response).
     * 
     * @param expectRequest true if a SAML 2 request is expected (an instance of
     *                      {@link org.opensaml.saml.saml2.core.RequestAbstractType},
     *                      false if a SAML 2 response is expected (an instance of
     *                      {@link org.opensaml.saml.saml1.core.ResponseAbstractType}
     * @param message the message to evaluate
     * 
     * @throws MessageDecodingException  if the message being evaluated is not the expected type
     */
    public static void checkSAML2MessageType(final boolean expectRequest, @Nonnull final SAMLObject message)
            throws MessageDecodingException {
        Constraint.isNotNull(message, "SAML 2 message cannot be null");

        if (expectRequest) {
            if (! org.opensaml.saml.saml2.core.RequestAbstractType.class.isInstance(message)) {
                throw new MessageDecodingException("Expected a SAML 2 request message, but saw: " 
                        + message.getClass().getName());
            }
        } else { 
            if (! StatusResponseType.class.isInstance(message)){ 
                throw new MessageDecodingException("Expected a SAML 2 response message, but saw: " 
                        + message.getClass().getName());
            }
        }
    }
    
    /**
     * Get the type of message being processed.
     * 
     * @param httpRequest the HTTP request
     * 
     * @return the message type, or null if the HTTP request is malformed with respect
     *         to SAML message parameters
     */
    @Nullable public static MessageType getMessageType(@Nonnull final HttpServletRequest httpRequest) {
        Constraint.isNotNull(httpRequest, "HttpServletRequest was null");
        
        final Set<String> messageTypeParamNames = MessageType.getAllParameterNames();
        final Set<String> requestParamNames = httpRequest.getParameterMap().keySet();
        
        final Set<String> messageParamNames = requestParamNames.stream()
                .filter(paramName -> messageTypeParamNames.contains(paramName))
                .collect(CollectionSupport.nonnullCollector(Collectors.toUnmodifiableSet())).get();
        LOG.debug("HttpServletRequest carried SAML message parameters: {}", messageParamNames);

        if (messageParamNames.isEmpty()) {
            LOG.warn("HttpServletRequest carried no SAML message parameters");
            return null;
        }
        if (messageParamNames.size() > 1) {
            LOG.warn("HttpServletRequest carried multiple SAML message type parameters: {}", messageParamNames);
            return null;
        }
        
        final String messageParamName = messageParamNames.iterator().next();

        return MessageType.fromParameterName(messageParamName);
    }
    
    /**
     * Validate that an HTTP request has a valid number of values for the specified message type.
     * 
     * @param httpRequest the HTTP request
     * @param messageType the message type
     * 
     * @throws MessageDecodingException if the HTTP request has an invalid number of values
     *         for the specified message type
     */
    public static void validateMessageTypeValues(@Nonnull final HttpServletRequest httpRequest,
            @Nonnull final MessageType messageType) throws MessageDecodingException {
        Constraint.isNotNull(httpRequest, "HttpServletRequest was null");
        Constraint.isNotNull(messageType, "MessageType was null");
        
        // Validate that the parameter does not have multiple values
        final String paramName = messageType.getParameterName();
        if (httpRequest.getParameterValues(paramName) != null
                && httpRequest.getParameterValues(paramName).length > 1) {
            throw new MessageDecodingException("HttpServletRequest had multiple values for parameter: "
                    + messageType.getParameterName());
        }
    }
    
    /**
     * Evaluate message size limit using the supplied parameters.
     * 
     * @param enforcementEnabled whether enforcement of message size limit is enabled
     * @param messageSizeLimit the message size limit
     * @param messageSize the received message size
     * 
     * @throws MessageDecodingException if evaluation is enabled and either 1) message size exceeds the limit
     *         or 2) the message size or limit is null
     */
    public static void evaluateMessageSizeLimit(final boolean enforcementEnabled,
            @Nullable final Integer messageSizeLimit, @Nullable final Integer messageSize)
                    throws MessageDecodingException {
        evaluateMessageSizeLimit(enforcementEnabled, messageSizeLimit, messageSize, "message");
    }

    /**
     * Evaluate message size limit using the supplied parameters.
     * 
     * @param enforcementEnabled whether enforcement of message size limit is enabled
     * @param messageSizeLimit the message size limit
     * @param messageSize the received message size
     * @param description description of what is being evaluated
     * 
     * @throws MessageDecodingException if evaluation is enabled and either 1) message size exceeds the limit
     *         or 2) the message size or limit is null
     */
    public static void evaluateMessageSizeLimit(final boolean enforcementEnabled,
            @Nullable final Integer messageSizeLimit, @Nullable final Integer messageSize,
            @Nullable final String description) throws MessageDecodingException {
        
        final String descriptionNormalized = description != null ? description : "message";
        
        if (enforcementEnabled)  {
            if (messageSize == null) {
                throw new MessageDecodingException(String.format("Enforcement of %s size limit enabled "
                        + "but size was undetermined", descriptionNormalized));
            }
            
            if (messageSizeLimit == null) {
                throw new MessageDecodingException(String.format("Enforcement of %s size limit enabled "
                        + "but size limit was undetermined", descriptionNormalized));
            }
            
            if (messageSize > messageSizeLimit) {
                LOG.warn("Size of {} was {} which exceeded configured size limit {}",
                        descriptionNormalized, messageSize, messageSizeLimit);
                throw new MessageDecodingException(String.format("Size of %s exceeded configured size limit",
                        descriptionNormalized));
            } else {
                LOG.debug("Size of {} was {} which was within configured size limit {}",
                        descriptionNormalized, messageSize, messageSizeLimit);
            }
        } else {
            LOG.debug("Enforcement of {} size limit is disabled, skipping check", descriptionNormalized);
        }
        
    }
    
    /**
     * Efficiently get the size of Base64-encoded data if it were decoded.
     * 
     * @param encoded the Base64-encoded data
     * @return the size of the data when decoded, in bytes
     */
    @Nonnull public static Integer getBase64Size(@Nullable final String encoded) {
        final String trimmed = StringSupport.trimOrNull(encoded);
        if (trimmed == null) {
            return 0;
        }
        LOG.trace("Trimmed Base64-encoded string was '{}'", trimmed);

        // Normalize the string by stripping the '=' padding
        final String noPadding = trimmed.split("=")[0];
        LOG.trace("Unpadded Base64-encoded string was '{}'", noPadding);
        LOG.trace("Length of the unpadded Base64-encoded string is {} characters", noPadding.length());

        final float floatSize = (float) (noPadding.length() * 0.75);
        LOG.trace("Raw float size of Base64-encoded data was {} bytes", floatSize);

        final Integer integerSize = (int)Math.floor(floatSize);
        LOG.trace("Integer size of Base64-encoded data was {} bytes", integerSize);

        return integerSize;
    }

    /**
     * Get the size of deflated and Base64-encoded data if it were decoded then inflated.
     * 
     * <p>
     * If <code>estimated</code> is true, then the size is estimated efficiently by simply applying
     * the specified <code>inflationFactor</code> against the result of {@link #getBase64Size(String)}.
     * This is very fast but the accuracy will depend entirely on the <code>inflationFactor</code>
     * that is used, so it must be chosen based on knowledge of the compressibility of the data.
     * </p>
     * 
     * <p>
     * If <code>estimated</code> is false, then the encoded data is actually Base64-decoded and then
     * inflated and the size is the length of the resulting <code>byte[]</code>. This is computationally
     * more expensive, but will give an exact size.
     * </p>
     * 
     * @param deflatedAndEncoded the deflated and Base64-encoded data
     * @param estimated flag indicating whether an exact or an estimated value should be determined
     * @param inflationFactor for estimated mode the multiplier applied against the Base64-decoded size. Should be
     *        greater than 1.0
     * @return the size of the data when Base64-decoded and inflated, in bytes
     * 
     * @throws MessageDecodingException if estimated was true and inflationFactor is null, or if there was
     *         a fatal error during Base64-decoding or inflation
     */
    @Nonnull public static Integer getDeflatedSize(@Nullable final String deflatedAndEncoded,
            final boolean estimated, @Nullable final Float inflationFactor) throws MessageDecodingException {

        final String trimmed = StringSupport.trimOrNull(deflatedAndEncoded);
        if (trimmed == null) {
            return 0;
        }
        LOG.trace("Trimmed deflated and Base64-encoded string was '{}'", trimmed);
        
        Integer size = null;
        if (estimated) {
            LOG.trace("Calculated deflated data size will be estimated");
            if (inflationFactor == null) {
                throw new MessageDecodingException("Estimate was specified by inflationFactor was null");
            }

            size = (int) Math.ceil(getBase64Size(trimmed) * inflationFactor);
        } else {
            LOG.trace("Calculated deflated data size will be exact");
            try {
                final byte[] decodedBytes = Base64.getMimeDecoder().decode(trimmed);
                try (final NoWrapAutoEndInflaterInputStream is =
                        new NoWrapAutoEndInflaterInputStream(new ByteArrayInputStream(decodedBytes))) {

                    size = is.readAllBytes().length;
                    
                } catch (final IOException e) {
                    throw new MessageDecodingException("Fatal error during inflation", e);
                }

            } catch (final IllegalArgumentException e) {
                throw new MessageDecodingException("Fatal error during Base64-decoding", e);
            }
        }

        LOG.trace("Calculated deflated data size result is {} bytes", size);
        return size;
    }
    
}
