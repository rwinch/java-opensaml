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

package org.opensaml.xmlsec.agreement.impl;

import java.security.SecureRandom;
import java.util.Base64;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.xmlsec.agreement.CloneableKeyAgreementParameter;
import org.opensaml.xmlsec.agreement.KeyAgreementException;
import org.opensaml.xmlsec.agreement.KeyAgreementParameter;
import org.opensaml.xmlsec.agreement.XMLExpressableKeyAgreementParameter;

import net.shibboleth.shared.annotation.constraint.NonnullAfterInit;
import net.shibboleth.shared.component.AbstractInitializableComponent;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.primitive.StringSupport;

/**
 * Key agreement parameter to support use of {@link org.opensaml.xmlsec.encryption.KANonce} values.
 */
public class KANonce extends AbstractInitializableComponent
    implements XMLExpressableKeyAgreementParameter, CloneableKeyAgreementParameter {
    
    /** Default length for generated salt, in bytes. */
    @Nonnull public static final Integer DEFAULT_GENERATED_LENGTH = 8;
    
    /** Base64-encoded nonce value. */
    @Nullable private String value;
    
    /** Generated salt length, in bytes. */
    @NonnullAfterInit private Integer generatedLength;
    
    /** SecureRandom generator for salt. */
    @NonnullAfterInit private SecureRandom secureRandom;
    
    /**
     * Get the Base64-encoded nonce value.
     * 
     * @return the nonce value
     */
    @Nullable public String getValue() {
        if (value == null && isInitialized()) {
            value = generateValue();
        }
        return value;
    }
    
    /**
     * Set the Base64-encoded nonce value.
     * 
     * @param newValue the nonce value
     */
    public void setValue(@Nullable final String newValue) {
        checkSetterPreconditions();
        value = StringSupport.trimOrNull(newValue);
    }
    
    /**
     * Get the generated length, in bytes.
     * 
     * @return the generated length, in bytes
     */
    @NonnullAfterInit public Integer getGeneratedLength() {
        return generatedLength;
    }
    
    /**
     * Set the generated length, in bytes.
     * 
     * @param length the generated length
     */
    public void setGeneratedLength(@Nullable final Integer length) {
        checkSetterPreconditions();
        generatedLength = length;
    }
    
    /**
     * Get the secure random generator.
     * 
     * <p>
     * Defaults to the platform default via <code>new SecureRandom()</code>
     * </p>
     * 
     * @return the secure random instance
     */
    @NonnullAfterInit public SecureRandom getRandom() {
        return secureRandom;
    }
    
    /**
     * Set the secure random generator.
     * 
     * <p>
     * Defaults to the platform default via <code>new SecureRandom()</code>
     * </p>
     * 
     * @param sr the secure random generator to set
     */
    public void setRandom(@Nullable final SecureRandom sr) {
        checkSetterPreconditions();
        secureRandom = sr;
    }

    /** {@inheritDoc} */
    protected void doInitialize() throws ComponentInitializationException {
        if (value != null) {
            try {
                Base64.getMimeDecoder().decode(value);
            } catch (final IllegalArgumentException e) {
                throw new ComponentInitializationException("Nonce value was not valid Base64", e);
            }
        }
        
        if (generatedLength == null) {
            generatedLength = DEFAULT_GENERATED_LENGTH;
        }
        
        if (secureRandom == null) {
            secureRandom = new SecureRandom();
        }
    }
    
    /**
     * Generate a new random value.
     * 
     * @return the generated value
     */
    protected String generateValue() {
        final byte[] valueBytes = new byte[generatedLength];
        secureRandom.nextBytes(valueBytes);
        return Base64.getEncoder().encodeToString(valueBytes);
    }

    /** {@inheritDoc} */
    public KANonce clone() {
        ifDestroyedThrowDestroyedComponentException();
        try {
            return (KANonce ) super.clone();
        } catch (final CloneNotSupportedException e) {
            // We know we are, so this will never happen
            return null;
        }
    }
    
    /** {@inheritDoc} */
    @Nonnull public XMLObject buildXMLObject() {
        final org.opensaml.xmlsec.encryption.KANonce nonce =
                (org.opensaml.xmlsec.encryption.KANonce) XMLObjectSupport
                    .buildXMLObject(org.opensaml.xmlsec.encryption.KANonce.DEFAULT_ELEMENT_NAME);
        
        nonce.setValue(getValue());
        return nonce;
    }
    
    /**
     * Create and initialize a new instance from the specified {@link XMLObject}.
     * 
     * @param xmlObject the XML object
     * 
     * @return new parameter instance
     * 
     * @throws ComponentInitializationException if component initialization fails
     */
    @Nonnull public static KANonce fromXMLObject(@Nonnull final org.opensaml.xmlsec.encryption.KANonce xmlObject) 
            throws ComponentInitializationException {
        Constraint.isNotNull(xmlObject, "XMLObject was null");
        
        if (StringSupport.trimOrNull(xmlObject.getValue()) == null) {
            throw new ComponentInitializationException("XML KANonce had a null or empty value");
        }
        
        final KANonce parameter = new KANonce();
        parameter.setValue(xmlObject.getValue());
        parameter.initialize();
        return parameter;
    }
    
    /**
     * Implementation of {@link KeyAgreementParameterParser}.
     */
    public static class Parser implements KeyAgreementParameterParser {

        /** {@inheritDoc} */
        public boolean handles(@Nonnull final XMLObject xmlObject) {
            return org.opensaml.xmlsec.encryption.KANonce.class.isInstance(xmlObject);
        }

        /** {@inheritDoc} */
        @Nonnull public KeyAgreementParameter parse(@Nonnull final XMLObject xmlObject) throws KeyAgreementException {
            // Sanity check
            if (!handles(xmlObject)) {
                throw new KeyAgreementException("This implementation does not handle: "
                        + xmlObject.getClass().getName());
            }
            
            try {
                return fromXMLObject(org.opensaml.xmlsec.encryption.KANonce.class.cast(xmlObject));
            } catch (final ComponentInitializationException e) {
                throw new KeyAgreementException(e);
            }
        }
        
    }

}