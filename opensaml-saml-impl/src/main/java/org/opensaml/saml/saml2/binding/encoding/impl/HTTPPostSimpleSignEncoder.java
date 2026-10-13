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

import java.io.UnsupportedEncodingException;
import java.util.Base64;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.apache.velocity.VelocityContext;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.binding.SAMLBindingSupport;
import org.opensaml.saml.common.messaging.SAMLMessageSecuritySupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.crypto.XMLSigningUtil;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.slf4j.Logger;

import com.google.common.base.Strings;

import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.primitive.LoggerFactory;
import net.shibboleth.shared.xml.SerializeSupport;

/**
 * SAML 2.0 HTTP-POST-SimpleSign binding message encoder.
 */
public class HTTPPostSimpleSignEncoder extends HTTPPostEncoder {
    
    /** Default template ID. */
    @Nonnull @NotEmpty public static final String DEFAULT_TEMPLATE_ID = "/templates/saml2-post-simplesign-binding.vm";

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(HTTPPostSimpleSignEncoder.class);
    
    /** Constructor. */
    public HTTPPostSimpleSignEncoder() {
        setVelocityTemplateId(DEFAULT_TEMPLATE_ID);
    }

    /** {@inheritDoc} */
    @Nonnull @NotEmpty public String getBindingURI() {
        return SAMLConstants.SAML2_POST_SIMPLE_SIGN_BINDING_URI;
    }

    /** {@inheritDoc} */
    protected void populateVelocityContext(@Nonnull final VelocityContext velocityContext,
            @Nonnull final MessageContext messageContext, @Nonnull @NotEmpty final String endpointURL)
                    throws MessageEncodingException {

        super.populateVelocityContext(velocityContext, messageContext, endpointURL);

        final SignatureSigningParameters signingParameters = 
                SAMLMessageSecuritySupport.getContextSigningParameters(messageContext);
        
        final Credential signingCredential = signingParameters != null
                ? signingParameters.getSigningCredential() : null;
        if (signingParameters == null || signingCredential == null) {
            log.debug("No signing credential was supplied, skipping HTTP-Post simple signing");
            return;
        }

        final String sigAlgURI = getSignatureAlgorithmURI(signingParameters);
        velocityContext.put("SigAlg", sigAlgURI);

        final String formControlData = buildFormDataToSign(velocityContext, messageContext, sigAlgURI);
        velocityContext.put("Signature", generateSignature(signingCredential, sigAlgURI, formControlData));

        
        final KeyInfoGenerator kiGenerator = signingParameters.getKeyInfoGenerator();
        if (kiGenerator != null) {
            final String kiBase64 = buildKeyInfo(signingCredential, kiGenerator);
            if (!Strings.isNullOrEmpty(kiBase64)) {
                velocityContext.put("KeyInfo", kiBase64);
            }
        }
    }

    /**
     * Build the {@link KeyInfo} from the signing credential.
     * 
     * @param signingCredential the credential used for signing
     * @param kiGenerator the generator for the KeyInfo
     * @throws MessageEncodingException thrown if there is an error generating or marshalling the KeyInfo
     * @return the marshalled, serialized and base64-encoded KeyInfo, or null if none was generated
     */
    @Nullable protected String buildKeyInfo(@Nonnull final Credential signingCredential,
            @Nonnull final KeyInfoGenerator kiGenerator) throws MessageEncodingException {

        try {
            final KeyInfo keyInfo = kiGenerator.generate(signingCredential);
            if (keyInfo != null) {
                final Marshaller marshaller =
                        XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(keyInfo);
                if (marshaller == null) {
                    log.error("No KeyInfo marshaller available from configuration");
                    throw new MessageEncodingException("No KeyInfo marshaller was configured");
                }
                final String kiXML = SerializeSupport.nodeToString(marshaller.marshall(keyInfo));
                final String kiBase64 = Base64.getEncoder().encodeToString(kiXML.getBytes());
                return kiBase64;
            }
            return null;
        } catch (final SecurityException e) {
            log.error("Error generating KeyInfo from signing credential: {}", e.getMessage());
            throw new MessageEncodingException("Error generating KeyInfo from signing credential", e);
        } catch (final MarshallingException e) {
            log.error("Error marshalling KeyInfo based on signing credential: {}", e.getMessage());
            throw new MessageEncodingException("Error marshalling KeyInfo based on signing credential", e);
        }
    }

    /**
     * Build the form control data string over which the signature is computed.
     * 
     * @param velocityContext the Velocity context which is already populated with the values for SAML message and relay
     *            state
     * @param messageContext the SAML message context being processed
     * @param sigAlgURI the signature algorithm URI
     * 
     * @throws MessageEncodingException if there is an issue building the form to sign. 
     * 
     * @return the form control data string for signature computation
     */
    @Nonnull protected String buildFormDataToSign(@Nonnull final VelocityContext velocityContext,
            @Nonnull final MessageContext messageContext, @Nonnull final String sigAlgURI)
                    throws MessageEncodingException {
        final StringBuilder builder = new StringBuilder();

        boolean isRequest = false;
        if (velocityContext.get("SAMLRequest") != null) {
            isRequest = true;
        }

        final String msgB64;
        if (isRequest) {
            msgB64 = (String) velocityContext.get("SAMLRequest");
        } else {
            msgB64 = (String) velocityContext.get("SAMLResponse");
        }
        // One or the other is populated...
        assert msgB64 != null;
      
        String msg = null;
        try {
            msg = new String(Base64.getMimeDecoder().decode(msgB64), "UTF-8");
        } catch (final UnsupportedEncodingException e) {
            // Should never happen, all JVM's required to support UTF-8           
            throw new MessageEncodingException("Unable to decode message as string, UTF-8 encoding is not supported",e);
        } catch (final IllegalArgumentException e) { 
            // Should never happen, original message is controlled and built by the IdP.
            throw new MessageEncodingException("Error base64-decoding the "+
                                            (isRequest ? "SAMLRequest" : "SAMLResponse"),e);
        }

        if (isRequest) {
            builder.append("SAMLRequest=" + msg);
        } else {
            builder.append("SAMLResponse=" + msg);
        }

        final String relayState = SAMLBindingSupport.getRelayState(messageContext);
        if (relayState != null) {
            builder.append("&RelayState=" + relayState);
        }

        builder.append("&SigAlg=" + sigAlgURI);

        return builder.toString();
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
     * Generates the signature over the string of concatenated form control data as indicated by the SimpleSign spec.
     * 
     * @param signingCredential credential that will be used to sign
     * @param algorithmURI algorithm URI of the signing credential
     * @param formData form control data to be signed
     * 
     * @return base64 encoded signature of form control data
     * 
     * @throws MessageEncodingException there is an error computing the signature
     */
    @Nonnull protected String generateSignature(@Nonnull final Credential signingCredential,
            @Nonnull final String algorithmURI, final String formData)
            throws MessageEncodingException {

        log.debug("Generating signature with algorithm URI '{}' over form control string '{}'", algorithmURI, formData);

        String b64Signature = null;
        try {
            final byte[] rawSignature =
                    XMLSigningUtil.signWithURI(signingCredential, algorithmURI, formData.getBytes("UTF-8"));
            b64Signature = Base64.getEncoder().encodeToString(rawSignature);
            log.debug("Generated digital signature value (base64-encoded) {}", b64Signature);
        } catch (final SecurityException e) {
            log.error("Error during URL signing process: {}", e.getMessage());
            throw new MessageEncodingException("Unable to sign form control string", e);
        } catch (final UnsupportedEncodingException e) {
            log.error("UTF-8 encoding is not supported, this VM is not Java compliant");
            throw new MessageEncodingException("Unable to encode message, UTF-8 encoding is not supported");
        }

        return b64Signature;
    }

}