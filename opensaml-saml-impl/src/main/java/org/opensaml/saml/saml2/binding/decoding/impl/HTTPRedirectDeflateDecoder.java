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
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

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
import org.opensaml.saml.config.SAMLConfigurationSupport;
import org.slf4j.Logger;

import com.google.common.base.Strings;

import jakarta.servlet.http.HttpServletRequest;
import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.collection.CollectionSupport;
import net.shibboleth.shared.collection.Pair;
import net.shibboleth.shared.io.NoWrapAutoEndInflaterInputStream;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.net.URISupport;
import net.shibboleth.shared.primitive.LoggerFactory;
import net.shibboleth.shared.primitive.StringSupport;

/**
 * SAML 2.0 HTTP Redirect decoder using the DEFLATE encoding method.
 * 
 * This decoder only supports DEFLATE compression.
 */
public class HTTPRedirectDeflateDecoder extends BaseSAMLHttpServletRequestDecoder implements SAMLMessageDecoder {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(HTTPRedirectDeflateDecoder.class);

    /** Optional {@link BindingDescriptor} to inject into {@link SAMLBindingContext} created. */
    @Nullable private BindingDescriptor bindingDescriptor;
    
    /** {@inheritDoc} */
    @Nonnull @NotEmpty public String getBindingURI() {
        return SAMLConstants.SAML2_REDIRECT_BINDING_URI;
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
        
        if (!"GET".equalsIgnoreCase(request.getMethod())) {
            throw new MessageDecodingException("This message decoder only supports the HTTP GET method");
        }
        
        final String samlEncoding = StringSupport.trimOrNull(request.getParameter("SAMLEncoding"));
        if (samlEncoding != null && !SAMLConstants.SAML2_BINDING_URL_ENCODING_DEFLATE_URI.equals(samlEncoding)) {
            throw new MessageDecodingException("Request indicated an unsupported SAMLEncoding: " + samlEncoding);
        }

        final String relayState = request.getParameter("RelayState");
        log.debug("Decoded RelayState: {}", relayState);
        SAMLBindingSupport.setRelayState(messageContext, relayState);

        String samlMessageEncoded = null;
        String samlMessageParamName = null;
        if (!Strings.isNullOrEmpty(request.getParameter("SAMLRequest"))) {
            samlMessageParamName = "SAMLRequest";
            samlMessageEncoded = request.getParameter("SAMLRequest");
        } else if (!Strings.isNullOrEmpty(request.getParameter("SAMLResponse"))) {
            samlMessageParamName = "SAMLResponse";
            samlMessageEncoded = request.getParameter("SAMLResponse");
        }
        assert samlMessageParamName != null;

        if (samlMessageEncoded != null) {
            try (final InputStream samlMessageIns = decodeMessage(samlMessageEncoded)) {
                final SAMLObject samlMessage = (SAMLObject) unmarshallMessage(samlMessageIns);
                SAMLBindingSupport.checkSAML2MessageType("SAMLRequest".equals(samlMessageParamName), samlMessage);
                messageContext.setMessage(samlMessage);
                log.debug("Decoded SAML message");
            } catch (final IOException e) {
                throw new MessageDecodingException("InputStream exception decoding SAML message", e);
            }
        } else {
            throw new MessageDecodingException(
                    "No SAMLRequest or SAMLResponse query path parameter, invalid SAML 2 HTTP Redirect message");
        }
        
        populateSimpleSignatureContext(messageContext, samlMessageParamName, samlMessageEncoded);

        populateBindingContext(messageContext);

        setMessageContext(messageContext);
    }

    /**
     * Build signed content string and populate the {@link SimpleSignatureContext}.
     * 
     * @param messageContext the current message context
     * @param samlMessageParamName the URL-decoded SAML message parameter name
     * @param samlMessage the URL-decoded Base64-encoded SAML message data
     * 
     * @throws MessageDecodingException if there is a fatal issue building the signed content
     */
    protected void populateSimpleSignatureContext(@Nonnull final MessageContext messageContext,
            @Nonnull final String samlMessageParamName, @Nonnull final String samlMessage)
                    throws MessageDecodingException {

        messageContext.ensureSubcontext(SimpleSignatureContext.class).setSignedContent(
                getSignedContent(samlMessageParamName, samlMessage));
    }
    
    /**
     * Get the signed content data.
     * 
     * @param samlMessageParamName the URL-decoded SAML message parameter name
     * @param samlMessage the URL-decoded Base64-encoded SAML message data
     * 
     * @return the signed content
     * 
     * @throws MessageDecodingException if there is a fatal issue building the signed content
     */
    @Nullable private byte[] getSignedContent(@Nonnull final String samlMessageParamName,
            @Nonnull final String samlMessage) throws MessageDecodingException {

        final HttpServletRequest request = getHttpServletRequest();
        if (request == null) {
            throw new MessageDecodingException("HttpServletRequest was null");
        }
        
        // We need the raw non-URL-decoded query string param values for HTTP-Redirect DEFLATE simple signature
        // validation.
        // We have to construct a string containing the signature input by accessing the
        // request directly. We can't use the decoded parameters because we need the raw
        // data and URL-encoding isn't canonical.
        final String queryString = request.getQueryString();
        log.debug("Constructing signed content string from URL query string {}", queryString);

        final String constructed = buildSignedContentString(queryString, samlMessageParamName, samlMessage);
        if (Strings.isNullOrEmpty(constructed)) {
            log.debug("Could not extract signed content string from query string");
            return null;
        }
        assert constructed != null;
        log.debug("Constructed signed content string for HTTP-Redirect DEFLATE {}", constructed);

        return constructed.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Extract the raw request parameters and build a string representation of the content that was signed.
     * 
     * @param queryString the raw HTTP query string from the request
     * @param samlMessageParamName the URL-decoded SAML message parameter name
     * @param samlMessage the URL-decoded Base64-encoded SAML message data
     * 
     * @return a string representation of the signed content
     * 
     * @throws MessageDecodingException thrown if there is an error during request processing
     */
    @Nullable @NotEmpty private String buildSignedContentString(@Nullable final String queryString,
            @Nonnull final String samlMessageParamName, @Nonnull final String samlMessage)
                    throws MessageDecodingException {

        final StringBuilder builder = new StringBuilder();

        if (!appendSAMLMessageParameter(builder, queryString, samlMessageParamName, samlMessage)) {
            log.info("Could not extract SAML message '{}' from the query string, cannot build simple signature content",
                    samlMessageParamName);
            return null;
        }

        // This is optional
        appendParameter(builder, queryString, "RelayState");

        // This is mandatory
        if (!appendParameter(builder, queryString, "SigAlg")) {
            log.debug("Signature algorithm could not be extracted from request, cannot build simple signature content");
            return null;
        }

        return builder.toString();
    }
    
    /**
     * Find the raw query string parameter indicated and append it to the string builder.
     * 
     * The appended value will be in the form 'paramName=paramValue' (minus the quotes).
     * 
     * @param builder string builder to which to append the parameter
     * @param queryString the URL query string containing parameters
     * @param paramName the name of the SAML message parameter to append
     * @param paramValue the value of the SAML message parameter to append
     * @return true if parameter was found, false otherwise
     */
    private boolean appendSAMLMessageParameter(@Nonnull final StringBuilder builder, @Nullable final String queryString,
            @Nonnull final String paramName, @Nonnull final String paramValue) {

        final List<Pair<String,String>> rawParams = URISupport.getRawQueryStringParameters(queryString, paramName)
                .stream()
                .filter(p -> Objects.equals(paramValue, URISupport.doURLDecode(p.getSecond())))
                .collect(CollectionSupport.nonnullCollector(Collectors.toList())).get();

        if (rawParams.isEmpty() || rawParams.size() > 1) {
            log.debug("SAML message raw params extraction resulted in an invalid # of params: {}", rawParams.size());
            return false;
        }
        
        final Pair<String,String> rawParam = rawParams.get(0);

        if (builder.length() > 0) {
            builder.append('&');
        }

        builder.append(rawParam.getFirst() + "=" + rawParam.getSecond());

        return true;
    }

    /**
     * Find the raw query string parameter indicated and append it to the string builder.
     * 
     * The appended value will be in the form 'paramName=paramValue' (minus the quotes).
     * 
     * @param builder string builder to which to append the parameter
     * @param queryString the URL query string containing parameters
     * @param paramName the name of the parameter to append
     * @return true if parameter was found, false otherwise
     */
    private boolean appendParameter(@Nonnull final StringBuilder builder, @Nullable final String queryString,
            @Nullable final String paramName) {
        final String rawParam = URISupport.getRawQueryStringParameter(queryString, paramName);
        if (rawParam == null) {
            return false;
        }

        if (builder.length() > 0) {
            builder.append('&');
        }

        builder.append(rawParam);

        return true;
    }

    /**
     * Base64 decodes the SAML message and then decompresses the message.
     * 
     * @param message Base64 encoded, DEFALTE compressed, SAML message
     * 
     * @return the SAML message
     * 
     * @throws MessageDecodingException thrown if the message can not be decoded
     */
    @Nonnull protected InputStream decodeMessage(@Nonnull final String message) throws MessageDecodingException {
        log.debug("Base64 decoding and inflating SAML message");

        try {
            final byte[] decodedBytes = Base64.getMimeDecoder().decode(message);
            return new NoWrapAutoEndInflaterInputStream(new ByteArrayInputStream(decodedBytes));
        } catch (final Exception e) {
            log.error("Unable to Base64 decode and inflate SAML message: {}", e.getMessage());
            throw new MessageDecodingException("Unable to Base64 decode and inflate SAML message", e);
        }
    }
    
    /**
     * Populate the context which carries information specific to this binding.
     * 
     * @param messageContext the current message context
     */
    protected void populateBindingContext(@Nonnull final MessageContext messageContext) {

        // TODO: make this throw MessageDecoderException so we can throw out here.
        final HttpServletRequest request = Constraint.isNotNull(getHttpServletRequest(), "HttpServletRequest was null");
        
        final SAMLBindingContext bindingContext = messageContext.ensureSubcontext(SAMLBindingContext.class);
        bindingContext.setBindingUri(getBindingURI());
        bindingContext.setBindingDescriptor(bindingDescriptor);
        bindingContext.setHasBindingSignature(
                !Strings.isNullOrEmpty(request.getParameter("Signature")));
        bindingContext.setIntendedDestinationEndpointURIRequired(SAMLBindingSupport.isMessageSigned(messageContext));
    }
    
    /** {@inheritDoc} */
    @Override
    @Nullable
    protected Integer getMessageSize() throws MessageDecodingException {
        final HttpServletRequest request = getHttpServletRequest();
        assert request != null;

        return SAMLBindingSupport.getDeflatedSize(
                request.getParameter(getMessageType().getParameterName()),
                SAMLConfigurationSupport.isDecoderEstimateInflatedSize(),
                SAMLConfigurationSupport.getDecoderInflationFactor());
    }

}