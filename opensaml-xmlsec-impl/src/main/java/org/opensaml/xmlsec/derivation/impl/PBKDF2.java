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

package org.opensaml.xmlsec.derivation.impl;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.xmlsec.agreement.CloneableKeyAgreementParameter;
import org.opensaml.xmlsec.agreement.KeyAgreementException;
import org.opensaml.xmlsec.agreement.KeyAgreementParameter;
import org.opensaml.xmlsec.agreement.XMLExpressableKeyAgreementParameter;
import org.opensaml.xmlsec.agreement.impl.KeyAgreementParameterParser;
import org.opensaml.xmlsec.algorithm.AlgorithmDescriptor;
import org.opensaml.xmlsec.algorithm.AlgorithmSupport;
import org.opensaml.xmlsec.algorithm.MACAlgorithm;
import org.opensaml.xmlsec.derivation.KeyDerivation;
import org.opensaml.xmlsec.derivation.KeyDerivationException;
import org.opensaml.xmlsec.derivation.KeyDerivationSupport;
import org.opensaml.xmlsec.encryption.IterationCount;
import org.opensaml.xmlsec.encryption.KeyDerivationMethod;
import org.opensaml.xmlsec.encryption.KeyLength;
import org.opensaml.xmlsec.encryption.PBKDF2Params;
import org.opensaml.xmlsec.encryption.PRF;
import org.opensaml.xmlsec.encryption.Salt;
import org.opensaml.xmlsec.encryption.Specified;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.signature.support.SignatureConstants;

import com.google.common.base.Charsets;

import net.shibboleth.shared.annotation.constraint.NonnullAfterInit;
import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.component.AbstractInitializableComponent;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.primitive.StringSupport;

/**
 * Implementation of PBKDF2 key derivation as defined in XML Encryption 1.1.
 */
public class PBKDF2 extends AbstractInitializableComponent
        implements KeyDerivation, XMLExpressableKeyAgreementParameter, CloneableKeyAgreementParameter {
    
    /** Default PRF. */
    @Nonnull @NotEmpty public static final String DEFAULT_PRF = SignatureConstants.ALGO_ID_MAC_HMAC_SHA256;
    
    /** Default iteration count. */
    @Nonnull public static final Integer DEFAULT_ITERATION_COUNT = 2000;
    
    /** Default length for generated salt, in bytes. */
    @Nonnull public static final Integer DEFAULT_GENERATED_SALT_LENGTH = 8;
    
    /** Base algorithm ID for PBKDF2 SecretKeyFactory. */
    @Nonnull private static final String PBKDF2_JCA_ALGORITHM_BASE = "PBKDF2With";
    
    /** Base64-encoded salt value. */
    @Nullable private String salt;
    
    /** Generated salt length, in bytes. */
    @NonnullAfterInit private Integer generatedSaltLength;
    
    /** SecureRandom generator for salt. */
    @NonnullAfterInit private SecureRandom secureRandom;
    
    /** Iteration count. */
    @NonnullAfterInit private Integer iterationCount;
    
    /** Key length, in <b>bits</b>. */
    @Nullable private Integer keyLength;
    
    /** Pseudo-random function algorithm. */
    @NonnullAfterInit private String prf;

    /** {@inheritDoc} */
    @Nonnull public String getAlgorithm() {
        return EncryptionConstants.ALGO_ID_KEYDERIVATION_PBKDF2;
    }
    
    /**
     * Get the Base64-encoded salt value.
     * 
     * @return the salt value
     */
    @Nullable public String getSalt() {
        return salt;
    }
    
    /**
     * Set the Base64-encoded salt value.
     * 
     * @param value the salt
     */
    public void setSalt(@Nullable final String value) {
        checkSetterPreconditions();
        salt = StringSupport.trimOrNull(value);
    }
    
    /**
     * Get the generated salt length, in bytes.
     * 
     * @return the generated salt length, in bytes
     */
    @NonnullAfterInit public Integer getGeneratedSaltLength() {
        return generatedSaltLength;
    }
    
    /**
     * Set the generated salt length, in bytes.
     * 
     * @param length the generated salt length
     */
    public void setGeneratedSaltLength(@Nullable final Integer length) {
        checkSetterPreconditions();
        generatedSaltLength = length;
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
    
    /**
     * Get the iteration count.
     * 
     * @return the iteration count
     */
    @NonnullAfterInit public Integer getIterationCount() {
        return iterationCount;
    }
    
    /**
     * Set the iteration count.
     * 
     * @param count the iteration count
     */
    public void setIterationCount(@Nullable final Integer count) {
        checkSetterPreconditions();
        iterationCount = count;
    }
    
    /**
     * Get the key length, in number of <b>bits</b>.
     * 
     * <p>
     * Note: KeyLength in expressed XML will be in <b>bytes</b>
     * </p>
     * 
     * @return the key length
     */
    @Nullable public Integer getKeyLength() {
         return keyLength;
    }
    
    /**
     * Set the key length, in number of <b>bits</b>.
     * 
     * <p>
     * Note: KeyLength in expressed XML will be in <b>bytes</b>
     * </p>
     * 
     * @param length the key length
     */
    public void setKeyLength(@Nullable final Integer length) {
        checkSetterPreconditions();
        keyLength = length;
    }
    
    /**
     * Get the pseudo-random function algorithm URI.
     * 
     * @return the algorithm URI
     */
    @NonnullAfterInit public String getPRF() {
        return prf;
    }
    
    /**
     * Set the pseudo-random function algorithm URI.
     * 
     * @param uri the PRF URI
     */
    public void setPRF(@Nullable final String uri) {
        checkSetterPreconditions();
        prf = StringSupport.trimOrNull(uri);
    }

    /** {@inheritDoc} */
    // Checkstyle: CyclomaticComplexity OFF
    protected void doInitialize() throws ComponentInitializationException {
        if (salt != null) {
            try {
                Base64.getMimeDecoder().decode(salt);
            } catch (final IllegalArgumentException e) {
                throw new ComponentInitializationException("Salt value was not valid Base64", e);
            }
        }
        
        if (generatedSaltLength == null) {
            generatedSaltLength = DEFAULT_GENERATED_SALT_LENGTH;
        }
        
        if (secureRandom == null) {
            secureRandom = new SecureRandom();
        }
        
        if (iterationCount == null) {
            iterationCount = DEFAULT_ITERATION_COUNT;
        }
        
        if (keyLength != null && keyLength % 8 != 0) {
            throw new ComponentInitializationException("Specified key length in bits is not a multiple of 8");
        }
        
        if (prf == null) {
            prf = DEFAULT_PRF;
        } else {
            final AlgorithmDescriptor descriptor = AlgorithmSupport.ensureGlobalAlgorithmRegistry().get(prf);
            if (descriptor == null) {
                throw new ComponentInitializationException("Specified PRF algorithm is unknown: " + prf);
            }
            if (!MACAlgorithm.class.isInstance(descriptor)) {
                throw new ComponentInitializationException("Specified PRF algorithm is not a MAC algorithm: " + prf);
            }
        }
    }
    // Checkstyle: CyclomaticComplexity ON

    /** {@inheritDoc} */
    @Nonnull public SecretKey derive(@Nonnull final byte[] secret, @Nonnull final String keyAlgorithm,
            @Nullable final Integer specifiedKeyLength) throws KeyDerivationException {
        Constraint.isNotNull(secret, "Secret byte[] was null");
        Constraint.isNotNull(keyAlgorithm, "Key algorithm was null");
        checkComponentActive();
        
        final String jcaKeyAlgorithm = KeyDerivationSupport.getJCAKeyAlgorithm(keyAlgorithm);
        
        final byte[] saltBytes = getEffectiveSalt();
        
        final Integer length = getEffectiveKeyLength(keyAlgorithm, specifiedKeyLength);
        
        final String jcaPRF = AlgorithmSupport.getAlgorithmID(prf);
        
        final char[] secretChars = new String(secret, Charsets.UTF_8).toCharArray();
        
        try {
            final PBEKeySpec spec = new PBEKeySpec(secretChars, saltBytes, iterationCount, length);
            final SecretKeyFactory skf = SecretKeyFactory.getInstance(PBKDF2_JCA_ALGORITHM_BASE + jcaPRF);
            return new SecretKeySpec(skf.generateSecret(spec).getEncoded(), jcaKeyAlgorithm); 
        } catch (final NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new KeyDerivationException("Error generating SecretKey via PBKDF2", e);
        }
    }
    
    /**
     * Get the effective salt bytes to use.
     * 
     * @return the salt bytes
     * 
     * @throws KeyDerivationException if the salt value can not be successfully resolved
     */
    protected byte[] getEffectiveSalt() throws KeyDerivationException {
        byte[] saltBytes = null;
        if (salt == null) {
            // Usually the originator/encrypting case. We generate and set it internally here so can emit in XML later.
            saltBytes = new byte[generatedSaltLength];
            secureRandom.nextBytes(saltBytes);
            salt = Base64.getEncoder().encodeToString(saltBytes);
        } else {
            // Usually the recipient/decrypting case, where value is parsed from the Salt XML Element.
            try {
                assert salt != null;
                saltBytes = Base64.getMimeDecoder().decode(salt);
            } catch (final IllegalArgumentException e) {
                // We already tested this during init so this shouldn't happen
                throw new KeyDerivationException("Error Base64-decoding supplied salt", e);
            }
        }
        return saltBytes;
    }

    /**
     * Get the effective key length, in bits.
     * 
     * @param keyAlgorithm the algorithm for which the derived key will be used
     * @param specifiedKeyLength the explicitly specified key length
     * 
     * @return the effective key length, in bits
     * 
     * @throws KeyDerivationException if the key length can not be successfully resolved
     */
    protected Integer getEffectiveKeyLength(@Nonnull final String keyAlgorithm,
            @Nullable final Integer specifiedKeyLength) throws KeyDerivationException {
        
        final Integer jcaKeyLength = KeyDerivationSupport.getEffectiveKeyLength(keyAlgorithm, specifiedKeyLength);
        
        if (keyLength == null) {
            // Usually the originator/encrypting case. We set it internally here so can emit in XML later.
            keyLength = jcaKeyLength;
        } else {
            // Usually the recipient/decrypting case, where value is parsed from the KeyLength XML Element.
            // Validate that specified key length value matches that of the specified algorithm URI.
            assert keyLength != null;
            if (!keyLength.equals(jcaKeyLength)) {
                throw new KeyDerivationException(String.format("Specified key length '%d' does not match URI: %s",
                        keyLength, keyAlgorithm));
            }
        }
        
        return keyLength;
    }

    /** {@inheritDoc} */
    public PBKDF2 clone() {
        try {
            return (PBKDF2) super.clone();
        } catch (final CloneNotSupportedException e) {
            // We know we are, so this will never happen
            return null;
        }
    }

    /** {@inheritDoc} */
    @Nonnull public XMLObject buildXMLObject() {
        checkComponentActive();
        
        // If initialized, iterationCount and PRF are guaranteed to be non-null.
        // These 2 would happen if initialized but derive(...) hasn't been called.
        if (keyLength == null) {
            throw new IllegalStateException("PBKDF2 is missing KeyLength element data");
        }
        if (salt == null) {
            throw new IllegalStateException("PBKDF2 is missing Salt element data");
        }
        
        final KeyDerivationMethod method =
                (KeyDerivationMethod) XMLObjectSupport.buildXMLObject(KeyDerivationMethod.DEFAULT_ELEMENT_NAME);
        method.setAlgorithm(getAlgorithm());
        
        final PBKDF2Params params =
                (PBKDF2Params) XMLObjectSupport.buildXMLObject(PBKDF2Params.DEFAULT_ELEMENT_NAME);
        
        final Salt xmlSalt = (Salt) XMLObjectSupport.buildXMLObject(Salt.DEFAULT_ELEMENT_NAME);
        final Specified  specified = (Specified) XMLObjectSupport.buildXMLObject(Specified.DEFAULT_ELEMENT_NAME);
        specified.setValue(salt);
        xmlSalt.setSpecified(specified);
        params.setSalt(xmlSalt);
        
        final IterationCount xmlIterationcount =
                (IterationCount) XMLObjectSupport.buildXMLObject(IterationCount.DEFAULT_ELEMENT_NAME);
        xmlIterationcount.setValue(iterationCount);
        params.setIterationCount(xmlIterationcount);
        
        final KeyLength xmlKeyLength = (KeyLength) XMLObjectSupport.buildXMLObject(KeyLength.DEFAULT_ELEMENT_NAME);
        // Note: We're tracking this in # of bits, but the XML element uses # of bytes.
        // It's already validated to be an exact multiple of 8.
        assert keyLength != null;
        xmlKeyLength.setValue(keyLength / 8);
        params.setKeyLength(xmlKeyLength);
        
        final PRF xmlPRF = (PRF) XMLObjectSupport.buildXMLObject(PRF.DEFAULT_ELEMENT_NAME);
        xmlPRF.setAlgorithm(prf);
        params.setPRF(xmlPRF);
        
        method.getUnknownXMLObjects().add(params);
        
        return method;
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
    @Nonnull public static PBKDF2 fromXMLObject(@Nonnull final KeyDerivationMethod xmlObject) 
            throws ComponentInitializationException {
        Constraint.isNotNull(xmlObject, "XMLObject was null");
        
        if (! EncryptionConstants.ALGO_ID_KEYDERIVATION_PBKDF2.equals(xmlObject.getAlgorithm())) {
            throw new ComponentInitializationException("KeyDerivationMethod contains unsupported algorithm: "
                    + xmlObject.getAlgorithm());
        }
        
        if (xmlObject.getUnknownXMLObjects().size() != 1 
                || xmlObject.getUnknownXMLObjects(PBKDF2Params.DEFAULT_ELEMENT_NAME).size() != 1) {
            throw new ComponentInitializationException("KeyDerivationMethod contains unsupported children");
        }
        
        final PBKDF2Params xmlParams =
                (PBKDF2Params) xmlObject.getUnknownXMLObjects(PBKDF2Params.DEFAULT_ELEMENT_NAME).get(0);
        assert xmlParams != null;
        return validateAndSetXMLObjectParameters(xmlParams);
    }
    
    /**
     * Validate the {@link PBKDF2Params} instance.
     * 
     * @param xmlParams the instance to validate
     * 
     * @return the initialized {@link PBKDF2} object
     * 
     * @throws ComponentInitializationException if the specified params fails validation of required values
     */
    // Checkstyle: CyclomaticComplexity OFF
    @Nonnull private static PBKDF2 validateAndSetXMLObjectParameters(@Nonnull final PBKDF2Params xmlParams)
            throws ComponentInitializationException {
        
        final IterationCount iterCount = xmlParams.getIterationCount();
        if (iterCount == null || iterCount.getValue() == null) {
            throw new ComponentInitializationException("PBKDF2-params did not contain IterationCount value");
        }
        
        final KeyLength keyLengthObject = xmlParams.getKeyLength();
        final Integer keyLength = keyLengthObject != null ? keyLengthObject.getValue() : null;
        if (keyLength == null) {
            throw new ComponentInitializationException("PBKDF2-params did not contain KeyLength value");
        }
        
        final PRF prf = xmlParams.getPRF();
        if (prf == null || prf.getAlgorithm() == null) {
            throw new ComponentInitializationException("PBKDF2-params did not contain PRF value");
        }
        
        if (prf.getParameters() != null) {
            throw new ComponentInitializationException("PBKDF2-params contained unsupported PRF parameters");
        }
        
        final Salt salt = xmlParams.getSalt();
        final Specified specified = salt != null ? salt.getSpecified() : null;
        if (specified == null || specified.getValue() == null) {
            throw new ComponentInitializationException("PBKDF2-params did not contain Salt Specified value");
        }
        
        final PBKDF2 param = new PBKDF2();
        
        param.setIterationCount(iterCount.getValue());

        // Note: We're tracking this in # of bits, but the XML element uses # of bytes.
        param.setKeyLength(keyLength * 8);
        param.setPRF(prf.getAlgorithm());
        param.setSalt(specified.getValue());
        
        param.initialize();
        return param;
    }
    // Checkstyle: CyclomaticComplexity ON
    
    /**
     * Implementation of {@link KeyAgreementParameterParser}.
     */
    public static class Parser implements KeyAgreementParameterParser {

        /** {@inheritDoc} */
        public boolean handles(@Nonnull final XMLObject xmlObject) {
            return KeyDerivationMethod.class.isInstance(xmlObject)
                    && EncryptionConstants.ALGO_ID_KEYDERIVATION_PBKDF2.equals(
                            KeyDerivationMethod.class.cast(xmlObject).getAlgorithm());
        }

        /** {@inheritDoc} */
        @Nonnull public KeyAgreementParameter parse(@Nonnull final XMLObject xmlObject) throws KeyAgreementException {
            // Sanity check
            if (!handles(xmlObject)) {
                throw new KeyAgreementException("This implementation does not handle: "
                        + xmlObject.getClass().getName());
            }
            
            try {
                return fromXMLObject(KeyDerivationMethod.class.cast(xmlObject));
            } catch (final ComponentInitializationException e) {
                throw new KeyAgreementException(e);
            }
        }
        
    }
    
}