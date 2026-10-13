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

package org.opensaml.saml.saml2.binding.decoding.impl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Base64;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.binding.BindingDescriptor;
import org.opensaml.saml.common.binding.SAMLBindingSupport;
import org.opensaml.saml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.saml.common.binding.impl.BaseSAMLHttpServletRequestDecoder;
import org.opensaml.saml.common.messaging.context.SAMLBindingContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.slf4j.Logger;

import com.google.common.base.Strings;

import jakarta.servlet.http.HttpServletRequest;
import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.collection.Pair;
import net.shibboleth.shared.primitive.LoggerFactory;

/** Message decoder implementing the SAML 2.0 HTTP POST binding. */
public class HTTPPostDecoder extends BaseSAMLHttpServletRequestDecoder implements SAMLMessageDecoder {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(HTTPPostDecoder.class);

    /** Optional {@link BindingDescriptor} to inject into {@link SAMLBindingContext} created. */
    @Nullable private BindingDescriptor bindingDescriptor;
    
    /** {@inheritDoc} */
    @Nonnull @NotEmpty public String getBindingURI() {
        return SAMLConstants.SAML2_POST_BINDING_URI;
    }
    
    /**
     * Get an optional {@link BindingDescriptor} to inject into {@link SAMLBindingContext} created.
     * 
     * @return binding descriptor
     */
    @Nullable public BindingDescriptor getBindingDescriptor() {
        return bindingDescriptor;
    }
    
    /**
     * Set an optional {@link BindingDescriptor} to inject into {@link SAMLBindingContext} created.
     * 
     * @param descriptor a binding descriptor
     */
    public void setBindingDescriptor(@Nullable final BindingDescriptor descriptor) {
        bindingDescriptor = descriptor;
    }

    /** {@inheritDoc} */
    protected void doDecode() throws MessageDecodingException {
        // We should do this but probably not until V6 and the destroy changes.
        //checkComponentActive();
        final MessageContext messageContext = new MessageContext();
        final HttpServletRequest request = getHttpServletRequest();
        if (request == null) {
            throw new MessageDecodingException("HttpServletRequest was null");
        }

        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            throw new MessageDecodingException("This message decoder only supports the HTTP POST method");
        }

        final String relayState = request.getParameter("RelayState");
        log.debug("Decoded SAML relay state of: {}", relayState);
        SAMLBindingSupport.setRelayState(messageContext, relayState);

        // The default impl is a ByteArrayInputStream, which really doesn't need to be closed.  But this could
        // be overridden, so be safe and make sure it gets closed.  Also for style and consistency.
        final Pair<InputStream,String> messageData = getBase64DecodedMessage(request);
        try (final InputStream base64DecodedMessage = messageData.getFirst()) {
            assert base64DecodedMessage != null;
            final SAMLObject inboundMessage = (SAMLObject) unmarshallMessage(base64DecodedMessage);
            final String samlMessageParamName = messageData.getSecond();
            assert samlMessageParamName != null;
            SAMLBindingSupport.checkSAML2MessageType("SAMLRequest".equals(samlMessageParamName), inboundMessage);
            messageContext.setMessage(inboundMessage);
            log.debug("Decoded SAML message");
        } catch (final IOException e) {
            throw new MessageDecodingException(e);
        }

        populateBindingContext(messageContext);
        
        setMessageContext(messageContext);
    }

    /**
     * Gets the Base64 encoded message from the request and decodes it.
     * 
     * @param request the inbound HTTP servlet request
     * 
     * @return decoded message
     * 
     * @throws MessageDecodingException thrown if the message does not contain a base64 encoded SAML message, 
     *                                      or the message can not be base64-decoded.
     */
    @Nonnull protected Pair<InputStream,String> getBase64DecodedMessage(@Nonnull final HttpServletRequest request)
            throws MessageDecodingException {
        log.debug("Getting Base64 encoded message from request");
        String samlMessageParamName = null;
        String encodedMessage = request.getParameter("SAMLRequest");
        if (Strings.isNullOrEmpty(encodedMessage)) {
            encodedMessage = request.getParameter("SAMLResponse");
            samlMessageParamName = "SAMLResponse";
        } else {
            samlMessageParamName = "SAMLRequest";
        }

        if (Strings.isNullOrEmpty(encodedMessage)) {
            log.error("Request did not contain either a SAMLRequest or "
                    + "SAMLResponse paramter.  Invalid request for SAML 2 HTTP POST binding.");
            throw new MessageDecodingException("No SAML message present in request");
        }
        assert encodedMessage != null;

        try {
            log.trace("Base64 decoding SAML message:\n{}", encodedMessage);
            final byte[] decodedBytes = Base64.getMimeDecoder().decode(encodedMessage);            
            log.trace("Decoded SAML message:\n{}", new String(decodedBytes));
            return new Pair<>(new ByteArrayInputStream(decodedBytes), samlMessageParamName);
            
        } catch (final IllegalArgumentException e) {        
            log.error("Unable to Base64 decode SAML message");
            throw new MessageDecodingException("Unable to Base64 decode SAML message",e);
        }      
    }
    
    /**
     * Populate the context which carries information specific to this binding.
     * 
     * @param messageContext the current message context
     */
    protected void populateBindingContext(@Nonnull final MessageContext messageContext) {
        final SAMLBindingContext bindingContext = messageContext.ensureSubcontext(SAMLBindingContext.class);
        bindingContext.setBindingUri(getBindingURI());
        bindingContext.setBindingDescriptor(bindingDescriptor);
        bindingContext.setHasBindingSignature(false);
        bindingContext.setIntendedDestinationEndpointURIRequired(SAMLBindingSupport.isMessageSigned(messageContext));
    }
    
    /** {@inheritDoc} */
    @Override
    @Nullable
    protected Integer getMessageSize() throws MessageDecodingException {
        final HttpServletRequest request = getHttpServletRequest();
        assert request != null;
        return SAMLBindingSupport.getBase64Size(
                request.getParameter(getMessageType().getParameterName()));
    }
    
}