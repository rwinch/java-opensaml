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

package org.opensaml.saml.saml2.binding.encoding.impl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

import javax.annotation.Nonnull;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.common.binding.SAMLBindingSupport;
import org.opensaml.saml.common.messaging.SAMLMessageSecuritySupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.StatusResponseType;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.crypto.XMLSigningUtil;
import org.slf4j.Logger;

import com.google.common.collect.Lists;

import jakarta.servlet.http.HttpServletResponse;
import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.collection.CollectionSupport;
import net.shibboleth.shared.collection.Pair;
import net.shibboleth.shared.io.NoWrapAutoEndDeflaterOutputStream;
import net.shibboleth.shared.net.URLBuilder;
import net.shibboleth.shared.primitive.LoggerFactory;
import net.shibboleth.shared.primitive.StringSupport;
import net.shibboleth.shared.servlet.HttpServletSupport;
import net.shibboleth.shared.xml.SerializeSupport;

/**
 * SAML 2.0 HTTP Redirect encoder using the DEFLATE encoding method.
 * 
 * This encoder only supports DEFLATE compression.
 */
public class HTTPRedirectDeflateEncoder extends BaseSAML2MessageEncoder {
    
    /** Params which are disallowed from appearing in the input endpoint URL. */
    @Nonnull private static final Set<String> DISALLOWED_ENDPOINT_QUERY_PARAMS = 
            CollectionSupport.setOf("SAMLEncoding", "SAMLRequest", "SAMLResponse", "RelayState", "SigAlg", "Signature");

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(HTTPRedirectDeflateEncoder.class);

    /** {@inheritDoc} */
    @Nonnull @NotEmpty public String getBindingURI() {
        return SAMLConstants.SAML2_REDIRECT_BINDING_URI;
    }

    /** {@inheritDoc} */
    protected void doEncode() throws MessageEncodingException {
        final MessageContext messageContext = getMessageContext();
        final Object outboundMessage = messageContext.getMessage();
        if (outboundMessage == null || !(outboundMessage instanceof SAMLObject)) {
            throw new MessageEncodingException("No outbound SAML message contained in message context");
        }

        final String endpointURL = getEndpointURL(messageContext).toString();
        assert endpointURL != null;

        removeSignature((SAMLObject) outboundMessage);

        final String encodedMessage = deflateAndBase64Encode((SAMLObject) outboundMessage);

        final String redirectURL = buildRedirectURL(messageContext, endpointURL, encodedMessage);

        final HttpServletResponse response = getHttpServletResponse();
        assert response != null;
        HttpServletSupport.addNoCacheHeaders(response);
        HttpServletSupport.setUTF8Encoding(response);

        try {
            response.sendRedirect(redirectURL);
        } catch (final IOException e) {
            throw new MessageEncodingException("Problem sending HTTP redirect", e);
        }
    }

    /**
     * Removes the signature from the protocol message.
     * 
     * @param message current message context
     */
    protected void removeSignature(@Nonnull final SAMLObject message) {
        if (message instanceof SignableSAMLObject) {
            final SignableSAMLObject signableMessage = (SignableSAMLObject) message;
            if (signableMessage.isSigned()) {
                log.debug("Removing SAML protocol message signature");
                signableMessage.setSignature(null);
            }
        }
    }

    /**
     * DEFLATE (RFC1951) compresses the given SAML message.
     * 
     * @param message SAML message
     * 
     * @return DEFLATE compressed message
     * 
     * @throws MessageEncodingException thrown if there is a problem compressing the message
     */
    @Nonnull protected String deflateAndBase64Encode(@Nonnull final SAMLObject message)
            throws MessageEncodingException {
        log.debug("Deflating and Base64 encoding SAML message");
        try {
            final String messageStr = SerializeSupport.nodeToString(marshallMessage(message));

            try (final ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
                    final DeflaterOutputStream deflaterStream =
                            new NoWrapAutoEndDeflaterOutputStream(bytesOut, Deflater.DEFLATED)) {

                deflaterStream.write(messageStr.getBytes("UTF-8"));
                deflaterStream.finish();

                return Base64.getEncoder().encodeToString(bytesOut.toByteArray());
            }            
        } catch (final IOException e) {
            throw new MessageEncodingException("Unable to DEFLATE and Base64 encode SAML message", e);
        } 
    }

    /**
     * Builds the URL to redirect the client to.
     * 
     * @param messageContext current message context
     * @param endpoint endpoint URL to send encoded message to
     * @param message Deflated and Base64 encoded message
     * 
     * @return URL to redirect client to
     * 
     * @throws MessageEncodingException thrown if the SAML message is neither a RequestAbstractType or Response
     */
    @Nonnull protected String buildRedirectURL(@Nonnull final MessageContext messageContext,
            @Nonnull @NotEmpty final String endpoint, @Nonnull @NotEmpty final String message)
                    throws MessageEncodingException {
        log.debug("Building URL to redirect client to");
        
        URLBuilder urlBuilder = null;
        try {
            urlBuilder = new URLBuilder(endpoint);
        } catch (final MalformedURLException e) {
            throw new MessageEncodingException("Endpoint URL " + endpoint + " is not a valid URL", e);
        }

        final List<Pair<String, String>> queryParams = urlBuilder.getQueryParams();
        removeDisallowedQueryParams(queryParams);
        
        // This is a copy of any existing allowed params that were preserved.  Note that they will not be signed.
        final List<Pair<String, String>> originalParams = new ArrayList<>(queryParams);

        // We clear here so that existing params will not be signed, but can still use the URLBuilder#buildQueryString()
        // to build the string that will potentially be signed later. Add originalParms back in later.
        queryParams.clear();

        final SAMLObject outboundMessage = (SAMLObject) messageContext.getMessage();

        if (outboundMessage instanceof RequestAbstractType) {
            queryParams.add(new Pair<>("SAMLRequest", message));
        } else if (outboundMessage instanceof StatusResponseType) {
            queryParams.add(new Pair<>("SAMLResponse", message));
        } else {
            throw new MessageEncodingException(
                    "SAML message is neither a SAML RequestAbstractType or StatusResponseType");
        }

        final String relayState = SAMLBindingSupport.getRelayState(messageContext);
        if (SAMLBindingSupport.checkRelayState(relayState)) {
            queryParams.add(new Pair<>("RelayState", relayState));
        }

        final SignatureSigningParameters signingParameters = 
                SAMLMessageSecuritySupport.getContextSigningParameters(messageContext);
        final Credential signingCred = signingParameters != null ? signingParameters.getSigningCredential() : null;
        if (signingParameters != null && signingCred != null) {
            final String sigAlgURI =  getSignatureAlgorithmURI(signingParameters);
            final Pair<String, String> sigAlg = new Pair<>("SigAlg", sigAlgURI);
            queryParams.add(sigAlg);
            final String sigMaterial = urlBuilder.buildQueryString();
            assert sigMaterial != null;

            queryParams.add(new Pair<>("Signature", generateSignature(signingCred, sigAlgURI, sigMaterial)));

            // Add original params to the beginning of the list preserving their original order.
            if (!originalParams.isEmpty()) {
                for (final Pair<String, String> param : Lists.reverse(originalParams)) {
                    queryParams.add(0, param);
                }
            }

        } else {
            log.debug("No signing credential was supplied, skipping HTTP-Redirect DEFLATE signing");
            queryParams.addAll(originalParams);
        }
        
        return urlBuilder.buildURL();
    }

    /**
     * Remove disallowed query params from the supplied list.
     * 
     * @param queryParams the list of query params on which to operate
     */
    protected void removeDisallowedQueryParams(@Nonnull final List<Pair<String, String>> queryParams) {
        final Iterator<Pair<String,String>> iter = queryParams.iterator();
        while (iter.hasNext()) {
            final String paramName = StringSupport.trimOrNull(iter.next().getFirst());
            if (DISALLOWED_ENDPOINT_QUERY_PARAMS.contains(paramName)) {
                log.debug("Removing disallowed query param '{}' from endpoint URL", paramName);
                iter.remove();
            }
        }
    }

    /**
     * Gets the signature algorithm URI to use.
     * 
     * @param signingParameters the signing parameters to use
     * 
     * @return signature algorithm to use with the associated signing credential
     * 
     * @throws MessageEncodingException thrown if the algorithm URI is not supplied explicitly and 
     *          could not be derived from the supplied credential
     */
    @Nonnull protected String getSignatureAlgorithmURI(@Nonnull final SignatureSigningParameters signingParameters)
            throws MessageEncodingException {
        
        final String alg = signingParameters.getSignatureAlgorithm();
        if (alg != null) {
            return alg;
        }

        throw new MessageEncodingException("The signing algorithm URI could not be determined");
    }

    /**
     * Generates the signature over the query string.
     * 
     * @param signingCredential credential that will be used to sign query string
     * @param algorithmURI algorithm URI of the signing credential
     * @param queryString query string to be signed
     * 
     * @return base64 encoded signature of query string
     * 
     * @throws MessageEncodingException there is an error computing the signature
     */
    @Nonnull protected String generateSignature(@Nonnull final Credential signingCredential,
            @Nonnull final String algorithmURI, @Nonnull final String queryString) throws MessageEncodingException {

        log.debug("Generating signature with algorithm URI '{}' over query string '{}'", algorithmURI, queryString);

        try {
            final byte[] rawSignature =
                    XMLSigningUtil.signWithURI(signingCredential, algorithmURI, queryString.getBytes("UTF-8"));
            final String b64Signature = Base64.getEncoder().encodeToString(rawSignature);
            log.debug("Generated digital signature value (base64-encoded) {}", b64Signature);
            return b64Signature;
        } catch (final SecurityException e) {
            log.error("Error during URL signing process: {}", e.getMessage());
            throw new MessageEncodingException("Unable to sign URL query string", e);
        } catch (final UnsupportedEncodingException e) {
            // UTF-8 encoding is required to be supported by all JVMs
            throw new MessageEncodingException("Unable to access UTF-8 character encoding?", e);
        }
    }

}