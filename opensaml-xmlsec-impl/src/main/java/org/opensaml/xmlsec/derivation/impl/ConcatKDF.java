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

import java.util.HexFormat;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.params.KDFParameters;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.xmlsec.agreement.CloneableKeyAgreementParameter;
import org.opensaml.xmlsec.agreement.KeyAgreementException;
import org.opensaml.xmlsec.agreement.KeyAgreementParameter;
import org.opensaml.xmlsec.agreement.XMLExpressableKeyAgreementParameter;
import org.opensaml.xmlsec.agreement.impl.KeyAgreementParameterParser;
import org.opensaml.xmlsec.algorithm.AlgorithmDescriptor;
import org.opensaml.xmlsec.algorithm.AlgorithmSupport;
import org.opensaml.xmlsec.algorithm.DigestAlgorithm;
import org.opensaml.xmlsec.derivation.KeyDerivation;
import org.opensaml.xmlsec.derivation.KeyDerivationException;
import org.opensaml.xmlsec.derivation.KeyDerivationSupport;
import org.opensaml.xmlsec.encryption.ConcatKDFParams;
import org.opensaml.xmlsec.encryption.KeyDerivationMethod;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.signature.DigestMethod;
import org.opensaml.xmlsec.signature.support.SignatureConstants;

import com.google.common.primitives.Bytes;

import net.shibboleth.shared.annotation.constraint.NonnullAfterInit;
import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.component.AbstractInitializableComponent;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.primitive.StringSupport;

/**
 * Implementation of ConcatKDF key derivation as defined in XML Encryption 1.1.
 * 
 * <p>
 * The following rules apply to the concatenation parameters:
 * </p>
 * 
 * <ul>
 *  <li>AlgorithmID</li>
 *  <li>PartyUInfo</li>
 *  <li>PartyVInfo</li>
 *  <li>SuppPubInfo</li>
 *  <li>SuppPrivInfo</li>
 * </ul>
 * 
 * <p>
 * Configured parameter string values must conform to the XML <code>hexBinary</code> representation defined in
 * XML Encryption 1.1, section 5.4.1, except in <b>unpadded</b> form, with number of padding bits not indicated.
 * Per the recommendation in the XML Encryption specification, this implementation only supports whole byte
 * (bye-aligned) values, not arbitrary length bit-strings as theoretically allowed in the NIST specification,
 * so the # of padding bits for each parameter value in the XML representation must and will always be 0.
 * This means the methods {@link #unpadParam(String, String)} and {@link #fromXMLObject(KeyDerivationMethod)}
 * which consume external values from the XML representation will throw if the number of indicated padding bits
 * is non-zero. Similarly {@link #buildXMLObject()} will always emit values which indicate 0 padding bits.
 * </p>
 * 
 */
public class ConcatKDF extends AbstractInitializableComponent
        implements KeyDerivation, XMLExpressableKeyAgreementParameter, CloneableKeyAgreementParameter {
    
    /** Default digest method. */
    @Nonnull @NotEmpty public static final String DEFAULT_DIGEST_METHOD = EncryptionConstants.ALGO_ID_DIGEST_SHA256;
    
    /** Digest method. */
    @NonnullAfterInit private String digestMethod;
    
    /** AlgorithmID. */
    @Nullable private String algorithmID;
    
    /** PartyUInfo. */
    @Nullable private String partyUInfo;
   
    /** PartyVInfo. */
    @Nullable private String partyVInfo;

    /** SuppPubInfo. */
    @Nullable private String suppPubInfo;

    /** SuppPrivInfo. */
    @Nullable private String suppPrivInfo;

    /** {@inheritDoc} */
    @Nonnull public String getAlgorithm() {
        return EncryptionConstants.ALGO_ID_KEYDERIVATION_CONCATKDF;
    }
    
    /**
     * Get the digest method algorithm URI.
     * 
     * @return the algorithm URI
     */
    @NonnullAfterInit public String getDigestMethod() {
        return digestMethod;
    }

    /**
     * Set the digest method algorithm URI.
     * 
     * @param newDigestMethod the algorithm URI
     */
    public void setDigestMethod(@Nullable final String newDigestMethod) {
        checkSetterPreconditions();
        digestMethod = StringSupport.trimOrNull(newDigestMethod);
    }

    /**
     * Get the AlgorithmID in its unpadded hex-encoded form.
     * 
     * @return the AlgorithmID
     */
    @Nullable public String getAlgorithmID() {
        return algorithmID;
    }

    /**
     * Set the AlgorithmID in its unpadded hex-encoded form.
     * 
     * @param newAlgorithmID the AlgorithmID
     */
    public void setAlgorithmID(@Nullable final String newAlgorithmID) {
        checkSetterPreconditions();
        algorithmID = StringSupport.trimOrNull(newAlgorithmID);
    }

    /**
     * Get the PartyUInfo in its unpadded hex-encoded form.
     * 
     * @return the PartyUInfo
     */
    @Nullable public String getPartyUInfo() {
        return partyUInfo;
    }

    /**
     * Set the PartyUInfo in its unpadded hex-encoded form.
     * 
     * @param newPartyUInfo the PartyUInfo
     */
    public void setPartyUInfo(@Nullable final String newPartyUInfo) {
        checkSetterPreconditions();
        partyUInfo = StringSupport.trimOrNull(newPartyUInfo);
    }

    /**
     * Get the PartyVInfo in its unpadded hex-encoded form.
     * 
     * @return the PartyUInfo
     */
    @Nullable public String getPartyVInfo() {
        return partyVInfo;
    }

    /**
     * Set the PartyVInfo in its unpadded hex-encoded form.
     * 
     * @param newPartyVInfo the PartyVInfo
     */
    public void setPartyVInfo(@Nullable final String newPartyVInfo) {
        checkSetterPreconditions();
        partyVInfo = StringSupport.trimOrNull(newPartyVInfo);
    }

    /**
     * Get the SuppPubInfo in its unpadded hex-encoded form.
     * 
     * @return the SuppPubInfo
     */
    @Nullable public String getSuppPubInfo() {
        return suppPubInfo;
    }

    /**
     * Set the SuppPubInfo in its unpadded hex-encoded form.
     * 
     * @param newSuppPubInfo the SuppPubInfo
     */
    public void setSuppPubInfo(@Nullable final String newSuppPubInfo) {
        checkSetterPreconditions();
        suppPubInfo = StringSupport.trimOrNull(newSuppPubInfo);
    }

    /**
     * Get the SuppPrivInfo in its unpadded hex-encoded form.
     * 
     * @return the SuppPrivInfo
     */
    @Nullable public String getSuppPrivInfo() {
        return suppPrivInfo;
    }

    /**
     * Set the SuppPrivInfo in its unpadded hex-encoded form.
     * 
     * @param newSuppPrivInfo the SuppPrivInfo
     */
    public void setSuppPrivInfo(@Nullable final String newSuppPrivInfo) {
        checkSetterPreconditions();
        suppPrivInfo = StringSupport.trimOrNull(newSuppPrivInfo);
    }

    /** {@inheritDoc} */
    protected void doInitialize() throws ComponentInitializationException {
        try {
            decodeParam(algorithmID, "AlgorithmID");
            decodeParam(partyUInfo, "PartyUInfo");
            decodeParam(partyVInfo, "PartyVInfo");
            decodeParam(suppPubInfo, "SuppPubInfo");
            decodeParam(suppPrivInfo, "SuppPrivInfo");
        } catch (final KeyDerivationException e) {
            throw new ComponentInitializationException("Invalid ConcatKDF param value", e);
        }
                
        if (digestMethod == null) {
            digestMethod = DEFAULT_DIGEST_METHOD;
        } else {
            final AlgorithmDescriptor descriptor = AlgorithmSupport.ensureGlobalAlgorithmRegistry().get(digestMethod);
            if (descriptor == null) {
                throw new ComponentInitializationException("Specified digest algorithm is unknown: " + digestMethod);
            }
            if (!DigestAlgorithm.class.isInstance(descriptor)) {
                throw new ComponentInitializationException("Specified digest algorithm is not a digest algorithm: "
                        + digestMethod);
            }
            try {
                // We don't store this off for later use b/c these appear to be non-thread-safe, per-use instances,
                // so we get a new one each time in derive(...).
                assert digestMethod!=null;
                getDigestInstance(digestMethod);
            } catch (final KeyDerivationException e) {
                throw new ComponentInitializationException("Unable to obtain digest instance", e);
            }
        }
    }

    /** {@inheritDoc} */
    @Nonnull public SecretKey derive(@Nonnull final byte[] secret, @Nonnull final String keyAlgorithm,
            @Nullable final Integer keyLength) throws KeyDerivationException {
        Constraint.isNotNull(secret, "Secret byte[] was null");
        Constraint.isNotNull(keyAlgorithm, "Key algorithm was null");
        checkComponentActive();
        
        final String jcaKeyAlgorithm = KeyDerivationSupport.getJCAKeyAlgorithm(keyAlgorithm);
        
        final Integer jcaKeyLength = KeyDerivationSupport.getEffectiveKeyLength(keyAlgorithm, keyLength);
        
        final byte[] otherInfo = Bytes.concat(
                decodeParam(algorithmID, "AlgorithmID"),
                decodeParam(partyUInfo, "PartyUInfo"),
                decodeParam(partyVInfo, "PartyVInfo"),
                decodeParam(suppPubInfo, "SuppPubInfo"),
                decodeParam(suppPrivInfo, "SuppPrivInfo"));
        assert otherInfo!=null;
        final byte[] keyBytes = derive(secret, otherInfo, jcaKeyLength);
    
        return new SecretKeySpec(keyBytes, jcaKeyAlgorithm); 
    }
    
    /**
     * Derive the key bytes.
     * 
     * <p>
     * This re-factored method mostly exists to facilitate unit testing using external test vectors
     * which only specify the OtherInfo as an input, rather than its 5 constituent parts
     * as defined in NIST SP 800-56A and XML Encryption 1.1.
     * </p>
     * 
     * @param secret the input secret from which to derive the key
     * @param otherInfo the OtherInfo bit string as defined in NIST SP 800-56A
     * @param keyLength the length of the derived key, in bits
     * 
     * @return the derived key bytes
     * 
     * @throws KeyDerivationException if key derivation does not complete successfully
     */
    protected byte[] derive(@Nonnull final byte[] secret, @Nonnull final byte[] otherInfo,
            @Nonnull final Integer keyLength) throws KeyDerivationException {
        
        assert digestMethod!=null;
        final Digest digest = getDigestInstance(digestMethod);
        
        final ConcatenationKDFGenerator concatKDF = new ConcatenationKDFGenerator(digest);
        final KDFParameters kdfParams = new KDFParameters(secret, otherInfo);
        concatKDF.init(kdfParams);
        
        final int lengthInBytes = keyLength/8;
    
        final byte[] keyBytes = new byte[lengthInBytes];
        concatKDF.generateBytes(keyBytes, 0, lengthInBytes);
    
        return keyBytes;
    }

    /**
     * Get a new instance of the Bouncy Castle {@link Digest} for the specified digest algorithm URI.
     * 
     * @param digestURI the digest algorithm URI
     * 
     * @return a new corresponding instance of BC Digest
     * 
     * @throws KeyDerivationException if the specified digest algorithm is unsupported
     */
    @Nonnull protected Digest getDigestInstance(@Nonnull final String digestURI) throws KeyDerivationException {
        switch(digestURI) {
            case SignatureConstants.ALGO_ID_DIGEST_SHA1:
                return new SHA1Digest();
            case SignatureConstants.ALGO_ID_DIGEST_SHA224:
                return new SHA224Digest();
            case SignatureConstants.ALGO_ID_DIGEST_SHA256:
                return new SHA256Digest();
            case SignatureConstants.ALGO_ID_DIGEST_SHA384:
                return new SHA384Digest();
            case SignatureConstants.ALGO_ID_DIGEST_SHA512:
                return new SHA512Digest();
            case SignatureConstants.ALGO_ID_DIGEST_RIPEMD160:
                return new RIPEMD160Digest();
            default:
                throw new KeyDerivationException("Specified digest algorithm is unsupported: " + digestURI);
        }
    }

    /** {@inheritDoc} */
    public ConcatKDF clone() {
        try {
            return (ConcatKDF) super.clone();
        } catch (final CloneNotSupportedException e) {
            // We know we are, so this will never happen
            return null;
        }
    }

    /**
     * Decode the specified concatenation parameter value for input to the derivation operation.
     * 
     * @param value the value to process
     * @param name the name of the value being processed, for diagnostic purposes
     * 
     * @return the decoded value, which may be an empty array
     * 
     * @throws KeyDerivationException if parameter value could not be decoded successfully
     */
    @Nonnull protected byte[] decodeParam(@Nullable final String value, @Nonnull final String name)
            throws KeyDerivationException {
        
        final String trimmed = StringSupport.trimOrNull(value);
        if (trimmed == null) {
            return new byte[]{};
        }
        
        byte[] decoded = null;
        try {
            decoded = HexFormat.of().parseHex(trimmed);
        } catch (final IllegalArgumentException e) {
            throw new KeyDerivationException("ConcatKDF parameter was not valid hex-encoded value: " + name, e);
        }
        assert decoded!=null;
        return decoded;
    }
    
    /**
     * Pad the specified concatenation parameter value for output in the formed required by 
     * XML Encryption 1.1.
     * 
     * <p>
     * No syntactic validation is done on the input value.  Since only whole byte-aligned values are supported,
     * this method merely prepends "00" to indicate 0 padding bits.
     * </p>
     * 
     * @param value the value to process
     * 
     * @return the padded value, which may be null
     */
    @Nullable protected static String padParam(@Nullable final String value) {
        
        final String trimmed = StringSupport.trimOrNull(value);
        if (trimmed == null) {
            return null;
        }
        
        return "00" + trimmed;
        
    }

    /**
     * Unpad the specified concatenation parameter value from the padded from required by XML Encryption 1.1
     * for input to the derivation operation.
     * 
     * <p>
     * Since only whole byte-aligned values are supported, this method requires input values to begin with "00",
     * indicating 0 padding bits.
     * </p>
     * 
     * @param value the value to process
     * @param name the name of the value being processed, for diagnostic purposes
     * 
     * @return the unpadded value, which may be null
     * 
     * @throws KeyDerivationException if the input value is invalid
     */
    @Nullable protected static String unpadParam(@Nullable final String value, @Nullable final String name)
            throws KeyDerivationException {
        
        final String trimmed = StringSupport.trimOrNull(value);
        if (trimmed == null) {
            return null;
        }
        
        if (trimmed.length() < 2) {
            throw new KeyDerivationException("ConcatKDF parameter was not a valid padded hexBinary value "
                    + "(too short): " + name);
        }
        if (trimmed.length() % 2 != 0) {
            throw new KeyDerivationException("ConcatKDF parameter was not a valid padded hexBinary value "
                    + "(odd number of hex digits): " + name);
        }
        
        // We only support whole byte-aligned values, so # of padding bits must always be 0
        if (!trimmed.startsWith("00")) {
            throw new KeyDerivationException("ConcatKDF parameter was not a valid padded hexBinary value "
                    + "(non-byte-aligned): " + name);
        }
        
        // As of OSJ-355, we treat "00" as a legal value, representing an empty bitstring.
        // The following will return "" in that case, which is ok.

        return trimmed.substring(2);
    }
    
    /** {@inheritDoc} */
    @Nonnull public XMLObject buildXMLObject() {
        checkComponentActive();
        
        final KeyDerivationMethod method =
                (KeyDerivationMethod) XMLObjectSupport.buildXMLObject(KeyDerivationMethod.DEFAULT_ELEMENT_NAME);
        method.setAlgorithm(getAlgorithm());
        
        final ConcatKDFParams params =
                (ConcatKDFParams) XMLObjectSupport.buildXMLObject(ConcatKDFParams.DEFAULT_ELEMENT_NAME);
        
        final DigestMethod xmlDigestMethod =
                (DigestMethod) XMLObjectSupport.buildXMLObject(DigestMethod.DEFAULT_ELEMENT_NAME);
        xmlDigestMethod.setAlgorithm(digestMethod);
        params.setDigestMethod(xmlDigestMethod);
        
        params.setAlgorithmID(padParam(algorithmID));
        params.setPartyUInfo(padParam(partyUInfo));
        params.setPartyVInfo(padParam(partyVInfo));
        params.setSuppPubInfo(padParam(suppPubInfo));
        params.setSuppPrivInfo(padParam(suppPrivInfo));
        
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
    @Nonnull public static ConcatKDF fromXMLObject(@Nonnull final KeyDerivationMethod xmlObject) 
            throws ComponentInitializationException {
        Constraint.isNotNull(xmlObject, "XMLObject was null");
        
        if (! EncryptionConstants.ALGO_ID_KEYDERIVATION_CONCATKDF.equals(xmlObject.getAlgorithm())) {
            throw new ComponentInitializationException("KeyDerivationMethod contains unsupported algorithm: "
                    + xmlObject.getAlgorithm());
        }
        
        if (xmlObject.getUnknownXMLObjects().size() != 1 
                || xmlObject.getUnknownXMLObjects(ConcatKDFParams.DEFAULT_ELEMENT_NAME).size() != 1) {
            throw new ComponentInitializationException("KeyDerivationMethod contains unsupported children");
        }
        
        final ConcatKDFParams xmlParams =
                (ConcatKDFParams) xmlObject.getUnknownXMLObjects(ConcatKDFParams.DEFAULT_ELEMENT_NAME).get(0);
        
        final ConcatKDF parameter = new ConcatKDF();
        
        final DigestMethod digest = xmlParams.getDigestMethod();
        if (digest == null || digest.getAlgorithm() == null) {
            throw new ComponentInitializationException("KeyDerivationMethod did not contain DigestMethod value");
        }
        
        parameter.setDigestMethod(digest.getAlgorithm());
        
        try {
            parameter.setAlgorithmID(unpadParam(xmlParams.getAlgorithmID(), "AlgorithmID"));
            parameter.setPartyUInfo(unpadParam(xmlParams.getPartyUInfo(), "PartyUInfo"));
            parameter.setPartyVInfo(unpadParam(xmlParams.getPartyVInfo(), "PartyVInfo"));
            parameter.setSuppPubInfo(unpadParam(xmlParams.getSuppPubInfo(), "SuppPubInfo"));
            parameter.setSuppPrivInfo(unpadParam(xmlParams.getSuppPrivInfo(), "SuppPrivInfo"));
        } catch (final KeyDerivationException e) {
            throw new ComponentInitializationException("Invalid ConcatKDF param value", e);
        }
        
        parameter.initialize();
        
        return parameter;
    }
    
    /**
     * Implementation of {@link KeyAgreementParameterParser}.
     */
    public static class Parser implements KeyAgreementParameterParser {

        /** {@inheritDoc} */
        public boolean handles(@Nonnull final XMLObject xmlObject) {
            return KeyDerivationMethod.class.isInstance(xmlObject)
                    && EncryptionConstants.ALGO_ID_KEYDERIVATION_CONCATKDF.equals(
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