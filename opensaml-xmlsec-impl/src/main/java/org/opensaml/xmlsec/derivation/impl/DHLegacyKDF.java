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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.opensaml.xmlsec.algorithm.AlgorithmSupport;
import org.opensaml.xmlsec.derivation.KeyDerivationException;
import org.opensaml.xmlsec.derivation.KeyDerivationSupport;
import org.slf4j.Logger;

import com.google.common.base.Charsets;
import com.google.common.primitives.Bytes;

import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.primitive.LoggerFactory;
import net.shibboleth.shared.primitive.StringSupport;

/**
 * Implementation of the key derivation function used with Diffie-Hellman Key Agreement With Legacy Key Derivation
 * Function as defined in XML Encryption 1.1.
 */
public class DHLegacyKDF {
    
    /** Logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(DHLegacyKDF.class);
    
    /** Digest method. */
    @Nullable private String digestMethod;
    
    /** Nonce. */
    @Nullable private String nonce;

    /**
     * Get the digest method algorithm URI.
     * 
     * @return the algorithm URI
     */
    @Nullable public String getDigestMethod() {
        return digestMethod;
    }

    /**
     * Set the digest method algorithm URI.
     * 
     * @param newDigestMethod the algorithm URI
     */
    public void setDigestMethod(@Nullable final String newDigestMethod) {
        digestMethod = StringSupport.trimOrNull(newDigestMethod);
    }

    /**
     * Get the Base64-encoded nonce value.
     * 
     * @return the nonce value
     */
    @Nullable public String getNonce() {
        return nonce;
    }

    /**
     * Set the digest method algorithm URI.
     * 
     * @param newNonce the algorithm URI
     */
    public void setNonce(@Nullable final String newNonce) {
        nonce = StringSupport.trimOrNull(newNonce);
    }

    /**
     * Derrive secret key from inouts.
     * 
     * @param secret underlying secret
     * @param keyAlgorithm key algorithm
     * @param keyLength key length
     * 
     * @return derived key
     * 
     * @throws KeyDerivationException on failure
     */
    @Nonnull public SecretKey derive(@Nonnull final byte[] secret, @Nonnull final String keyAlgorithm,
            @Nullable final Integer keyLength) throws KeyDerivationException {
        Constraint.isNotNull(secret, "Secret byte[] was null");
        Constraint.isNotNull(keyAlgorithm, "Key algorithm was null");
        if (digestMethod == null) {
            throw new KeyDerivationException("Digest method not set");
        }
        
        final String jcaKeyAlgorithm = KeyDerivationSupport.getJCAKeyAlgorithm(keyAlgorithm);
        
        final Integer jcaKeyLength = KeyDerivationSupport.getEffectiveKeyLength(keyAlgorithm, keyLength);
        
        final byte[] keyBytes = deriveBytes(secret, keyAlgorithm, jcaKeyLength);
        
        return new SecretKeySpec(keyBytes, jcaKeyAlgorithm); 
    }

    /**
     * Derive the key bytes from the specified inputs.
     * 
     * @param secret the input secret
     * @param encryptionAlgorithm the encryption algorithm URI to be used with the derived key
     * @param keyLength the key length
     * 
     * @return derived bytes the derived key bytes
     * 
     * @throws KeyDerivationException if any of the inputs are invalid
     */
    protected byte[] deriveBytes(@Nonnull final byte[] secret, @Nonnull final String encryptionAlgorithm,
            @Nonnull final Integer keyLength) throws KeyDerivationException {
        
        byte[] derived = new byte[] {};
        
        assert digestMethod != null;
        final String jcaDigest = AlgorithmSupport.getAlgorithmID(digestMethod);
        if (jcaDigest == null) {
            log.warn("Could not resolve JCA algorithm ID from URI: {}", jcaDigest);
            throw new KeyDerivationException("Could not resolve JCA digest from URI: " + digestMethod);
        }
        
        try {
            final byte[] nonceBytes = nonce != null ? Base64.getMimeDecoder().decode(nonce) : new byte[] {};
            int counter = 0;
            while ((derived.length * 8) < keyLength) {
                derived = Bytes.concat(derived, digest(++counter, jcaDigest, secret, encryptionAlgorithm, keyLength,
                        nonceBytes));
            }
        } catch (final IllegalArgumentException e) { 
            log.error("Fatal error Base64-decoding supplied nonce value: {}", nonce, e);
            throw new KeyDerivationException("Fatal error decoding nonce", e);
        }
            
        return Arrays.copyOfRange(derived, 0, keyLength/8);
    }

    /**
     * Produce the digest of the specified inputs according to XML Encryption section 1.1, section 5.6.2.2.
     * 
     * @param counter the counter value
     * @param digestAlgorithm the JCA digest algorithm
     * @param secret the input secret
     * @param encryptionAlgorithm the encryption algorithm URI to be used with the derived key
     * @param keyLength the key length
     * @param nonceBytes the nonce, which may be an empty byte[] array, but not null
     * 
     * @return digest output for the specified inputs
     * 
     * @throws KeyDerivationException if any of the inputs are invalid
     */
    // CheckStyle: ParameterNumber OFF
    protected byte[] digest(final int counter, @Nonnull final String digestAlgorithm, @Nonnull final byte[] secret,
            @Nonnull final String encryptionAlgorithm, @Nonnull final Integer keyLength,
            @Nonnull final byte[] nonceBytes) throws KeyDerivationException {
        
        final byte[] digestInput = Bytes.concat(
                secret,
                String.format("%02d", counter).getBytes(Charsets.UTF_8),
                encryptionAlgorithm.getBytes(Charsets.UTF_8),
                nonceBytes,
                keyLength.toString().getBytes(Charsets.UTF_8));
        
        log.trace("Digest input for counter={} in hex was: {}", counter,
                HexFormat.of().withUpperCase().formatHex(digestInput));
        
        try {
            final MessageDigest md = MessageDigest.getInstance(digestAlgorithm);
            final byte[] output = md.digest(digestInput);
            log.trace("Digest output for counter={} in hex was: {}", counter,
                    HexFormat.of().withUpperCase().formatHex(output));
            return output;
        } catch (final NoSuchAlgorithmException e) {
            throw new KeyDerivationException("Fatal error computing digest for key derivation", e);
        }
    }
    // CheckStyle: ParameterNumber ON
    
}
