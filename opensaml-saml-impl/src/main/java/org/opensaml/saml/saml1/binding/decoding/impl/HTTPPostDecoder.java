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

package org.opensaml.saml.saml1.binding.decoding.impl;

import java.io.ByteArrayInputStream;
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
import org.opensaml.saml.saml1.core.ResponseAbstractType;
import org.slf4j.Logger;

import jakarta.servlet.http.HttpServletRequest;
import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.primitive.LoggerFactory;

/**
 * SAML 1.X HTTP POST message decoder.
 */
public class HTTPPostDecoder extends BaseSAMLHttpServletRequestDecoder implements SAMLMessageDecoder {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(HTTPPostDecoder.class);

    /** Optional {@link BindingDescriptor} to inject into {@link SAMLBindingContext} created. */
    @Nullable private BindingDescriptor bindingDescriptor;
    
    /** {@inheritDoc} */
    @Nonnull @NotEmpty public String getBindingURI() {
        return SAMLConstants.SAML1_POST_BINDING_URI;
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
        final MessageContext messageContext = new MessageContext();
        final HttpServletRequest request = getHttpServletRequest();
        assert request != null;
        
        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            throw new MessageDecodingException("This message decoder only supports the HTTP POST method");
        }

        final String relayState = request.getParameter("TARGET");
        log.debug("Decoded SAML relay state (TARGET parameter) of: {}", relayState);
        SAMLBindingSupport.setRelayState(messageContext, relayState);
        
        final String base64Message = request.getParameter("SAMLResponse");
        if (base64Message == null) {
            throw new MessageDecodingException("Missing SAMLResponse parameter");
        }
        final byte[] decodedBytes;
        try {
            decodedBytes = Base64.getMimeDecoder().decode(base64Message);
        } catch (final IllegalArgumentException e) {
            throw new MessageDecodingException("Unable to Base64 decode SAML message",e);
        }
        
        final SAMLObject inboundMessage = (SAMLObject) unmarshallMessage(new ByteArrayInputStream(decodedBytes));
        SAMLBindingSupport.checkSAML1MessageType(false, inboundMessage);
        messageContext.setMessage(inboundMessage);
        log.debug("Decoded SAML message");

        populateBindingContext(messageContext);
        
        setMessageContext(messageContext);            
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
        bindingContext.setIntendedDestinationEndpointURIRequired(
                messageContext.getMessage() instanceof ResponseAbstractType);
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