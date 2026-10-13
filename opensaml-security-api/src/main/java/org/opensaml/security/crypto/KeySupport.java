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

package org.opensaml.security.crypto;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.SecretKeySpec;

import net.shibboleth.shared.collection.LazyMap;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.primitive.LoggerFactory;

import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.cryptacular.util.KeyPairUtil;
import org.opensaml.security.SecurityException;
import org.slf4j.Logger;

import com.google.common.io.ByteStreams;
import com.google.common.io.Files;

/**
 * Helper methods for cryptographic keys and key pairs.
 */
public final class KeySupport {
    
    /** Logger. */
    @Nonnull private static final Logger LOG = LoggerFactory.getLogger(KeySupport.class);

    /** Maps key algorithms to the signing algorithm used in the key matching function. */
    @Nonnull private static final Map<String, String> keyMatchAlgorithms;

    /** Constructor. */
    private KeySupport() {
    }

    /**
     * Get the key length in bits of the specified key.
     * 
     * @param key the key to evaluate
     * @return length of the key in bits, or null if the length cannot be determined
     */
    @Nullable public static Integer getKeyLength(@Nonnull final Key key) {
        LOG.debug("Attempting to determine length of Key with algorithm '{}' and encoding format '{}'", 
                key.getAlgorithm(), key.getFormat());
        // TODO investigate if exists, and can/how to support, non-RAW format symmetric keys
        if (key instanceof SecretKey && JCAConstants.KEY_FORMAT_RAW.equals(key.getFormat())) {
            return key.getEncoded().length * 8;
        } else if (key instanceof RSAKey) {
            return ((RSAKey) key).getModulus().bitLength();
        } else if (key instanceof DSAKey) {
            return ((DSAKey) key).getParams().getP().bitLength();
        } else if (key instanceof ECKey) {
            return ((ECKey) key).getParams().getCurve().getField().getFieldSize();
        }
        LOG.debug("Unable to determine length in bits of specified Key instance");
        return null;
    }

    /**
     * Produces SecretKey instances specified as a raw byte[] plus a JCA key algorithm.
     * 
     * @param key the raw secret key bytes
     * @param algorithm the JCA key algorithm
     * 
     * @return the decoded key
     * 
     * @throws KeyException thrown if the key can not be decoded
     */
    @Nonnull public static SecretKey decodeSecretKey(@Nonnull final byte[] key, @Nonnull final String algorithm)
            throws KeyException {
        Constraint.isNotNull(key, "Secret key bytes can not be null");
        Constraint.isNotNull(algorithm, "Secret key algorithm can not be null");
        Constraint.isGreaterThanOrEqual(1, key.length, "Secret key bytes can not be empty");
        
        final int keyLengthBits = key.length*8;
        
        switch(algorithm) {
            case "AES":
                if (keyLengthBits != 128 && keyLengthBits != 192 && keyLengthBits != 256) {
                    throw new KeyException(String.format("Saw invalid key length %d for algorithm %s", 
                            keyLengthBits, "AES"));
                }
                break;
            case "DES":
                if (keyLengthBits != 64) {
                    throw new KeyException(String.format("Saw invalid key length %d for algorithm %s", 
                            keyLengthBits, "DES"));
                }
                break;
            case "DESede":
                if (keyLengthBits != 192 && keyLengthBits != 168) {
                    throw new KeyException(String.format("Saw invalid key length %d for algorithm %s", 
                            keyLengthBits, "DESede"));
                }
                break;
            default:
                LOG.debug("No length and sanity checking done for key with algorithm: {}", algorithm);
        }
        
        return new SecretKeySpec(key, algorithm);
    }

    /**
     * Decodes RSA/DSA public keys in DER-encoded "SubjectPublicKeyInfo" format.
     * 
     * @param key encoded key
     * 
     * @return decoded key
     * 
     * @throws KeyException thrown if the key cannot be decoded
     */
    @Nonnull public static PublicKey decodePublicKey(@Nonnull final byte[] key) throws KeyException {
        Constraint.isNotNull(key, "Encoded key bytes cannot be null");
        
        final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(key);
        try {
            return buildKey(keySpec, JCAConstants.KEY_ALGO_RSA);
        } catch (final KeyException ex) {
        }
        try {
            return buildKey(keySpec, JCAConstants.KEY_ALGO_DSA);
        } catch (final KeyException ex) {
        }
        try {
            return buildKey(keySpec, JCAConstants.KEY_ALGO_EC);
        } catch (final KeyException ex) {
        }
        throw new KeyException("Unsupported key type.");
    }

    /**
     * Decodes RSA/DSA private keys in DER, PEM, or PKCS#8 (encrypted or unencrypted) formats.
     * 
     * @param key encoded key
     * @param password decryption password or null if the key is not encrypted
     * 
     * @return decoded private key
     * 
     * @throws KeyException thrown if the key cannot be decoded
     */
    @Nonnull public static PrivateKey decodePrivateKey(@Nonnull final File key, @Nullable final char[] password)
            throws KeyException {
        Constraint.isNotNull(key, "Key file cannot be null");
        
        if (!key.exists()) {
            throw new KeyException("Key file " + key.getAbsolutePath() + " does not exist");
        }

        if (!key.canRead()) {
            throw new KeyException("Key file " + key.getAbsolutePath() + " is not readable");
        }

        try {
            return decodePrivateKey(Files.toByteArray(key), password);
        } catch (final IOException e) {
            throw new KeyException("Error reading Key file " + key.getAbsolutePath(), e);
        }
    }
    
    /**
     * Decodes RSA/DSA private keys in DER, PEM, or PKCS#8 (encrypted or unencrypted) formats. Note that this does 
     * <strong>not</strong> close the input stream. 
     * 
     * @param key encoded key
     * @param password decryption password or null if the key is not encrypted
     * 
     * @return decoded private key
     * 
     * @throws KeyException thrown if the key cannot be decoded
     */
    @Nonnull public static PrivateKey decodePrivateKey(@Nonnull final InputStream key, @Nullable final char[] password)
            throws KeyException {
        Constraint.isNotNull(key, "Key stream cannot be null");
        

        try {
            return decodePrivateKey(ByteStreams.toByteArray(key), password);
        } catch (final IOException e) {
            throw new KeyException("Error reading Key file ", e);
        }
    }
    

    /**
     * Decodes RSA/DSA private keys in DER, PEM, or PKCS#8 (encrypted or unencrypted) formats.
     * 
     * @param key encoded key
     * @param password decryption password or null if the key is not encrypted
     * 
     * @return decoded private key
     * 
     * @throws KeyException thrown if the key cannot be decoded
     */
    @Nonnull public static PrivateKey decodePrivateKey(@Nonnull final byte[] key, @Nullable final char[] password)
            throws KeyException {
        Constraint.isNotNull(key, "Encoded key bytes cannot be null");

        if (password != null && password.length > 0) {
            return KeyPairUtil.decodePrivateKey(key, password);
        }
        return KeyPairUtil.decodePrivateKey(key); 
    }
    
    /**
     * Derives the public key from either a DSA or RSA private key.
     * 
     * @param key the private key to derive the public key from
     * 
     * @return the derived public key
     * 
     * @throws KeyException thrown if the given private key is not a DSA or RSA key or there is a problem generating the
     *             public key
     */
    @Nonnull public static PublicKey derivePublicKey(@Nonnull final PrivateKey key) throws KeyException {
        final KeyFactory factory;
        if (key instanceof DSAPrivateKey) {
            final DSAPrivateKey dsaKey = (DSAPrivateKey) key;
            final DSAParams keyParams = dsaKey.getParams();
            final BigInteger y = keyParams.getG().modPow(dsaKey.getX(), keyParams.getP());
            final DSAPublicKeySpec pubKeySpec = new DSAPublicKeySpec(y, keyParams.getP(), 
                    keyParams.getQ(), keyParams.getG());

            try {
                factory = KeyFactory.getInstance(JCAConstants.KEY_ALGO_DSA);
                return factory.generatePublic(pubKeySpec);
            } catch (final GeneralSecurityException e) {
                throw new KeyException("Unable to derive public key from DSA private key", e);
            }
        } else if (key instanceof RSAPrivateCrtKey) {
            final RSAPrivateCrtKey rsaKey = (RSAPrivateCrtKey) key;
            final RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(rsaKey.getModulus(), rsaKey.getPublicExponent());

            try {
                factory = KeyFactory.getInstance(JCAConstants.KEY_ALGO_RSA);
                return factory.generatePublic(pubKeySpec);
            } catch (final GeneralSecurityException e) {
                throw new KeyException("Unable to derive public key from RSA private key", e);
            }
        } else if (key instanceof ECPrivateKey) {
            final ECPrivateKey ecKey = (ECPrivateKey) key;
            // Let BC do the math, by converting to BC's ECPoint for the multiply(BigInteger),
            // and then back to standard ECPoint
            final ECPoint ecPointPublic = EC5Util.convertPoint(EC5Util.convertPoint(
                    ecKey.getParams(), ecKey.getParams().getGenerator())
                        .multiply(ecKey.getS()));
            final ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(ecPointPublic, ecKey.getParams());

            try {
                factory = KeyFactory.getInstance(JCAConstants.KEY_ALGO_EC);
                return factory.generatePublic(pubKeySpec);
            } catch (final GeneralSecurityException e) {
                throw new KeyException("Unable to derive public key from EC private key", e);
            }
        } else {
            throw new KeyException("Private key was not a DSA, RSA or EC key");
        }
    }

    /**
     * Build Java DSA public key from base64 encoding.
     * 
     * @param base64EncodedKey base64-encoded DSA public key
     * @return a native Java DSAPublicKey
     * @throws KeyException thrown if there is an error constructing key
     */
    @Nonnull public static DSAPublicKey buildJavaDSAPublicKey(@Nonnull final String base64EncodedKey)
            throws KeyException {
        final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(base64DecodeOrThrow(base64EncodedKey));
        return (DSAPublicKey) buildKey(keySpec, JCAConstants.KEY_ALGO_DSA);
    }
    
    /**
     * Build Java DH public key from base64 encoding.
     * 
     * @param base64EncodedKey base64-encoded DH public key
     * @return a native Java DHPublicKey
     * @throws KeyException thrown if there is an error constructing key
     */
    @Nonnull public static DHPublicKey buildJavaDHPublicKey(@Nonnull final String base64EncodedKey)
            throws KeyException {
        final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(base64DecodeOrThrow(base64EncodedKey));
        return (DHPublicKey) buildKey(keySpec, JCAConstants.KEY_ALGO_DIFFIE_HELLMAN);
    }

    /**
     * Build Java RSA public key from base64 encoding.
     * 
     * @param base64EncodedKey base64-encoded RSA public key
     * @return a native Java RSAPublicKey
     * @throws KeyException thrown if there is an error constructing key
     */
    @Nonnull public static RSAPublicKey buildJavaRSAPublicKey(@Nonnull final String base64EncodedKey)
            throws KeyException {
        final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(base64DecodeOrThrow(base64EncodedKey));
        return (RSAPublicKey) buildKey(keySpec, JCAConstants.KEY_ALGO_RSA);
    }

    /**
     * Build Java EC public key from base64 encoding.
     * 
     * @param base64EncodedKey base64-encoded EC public key
     * @return a native Java ECPublicKey
     * @throws KeyException thrown if there is an error constructing key
     */
    @Nonnull public static ECPublicKey buildJavaECPublicKey(@Nonnull final String base64EncodedKey)
            throws KeyException {
        final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(base64DecodeOrThrow(base64EncodedKey));
        return (ECPublicKey) buildKey(keySpec, JCAConstants.KEY_ALGO_EC);
    }
    
    /**
     * Base64 decode the input string, if it fails to decode throw a {@link KeyException} 
     * wrapping the original exception.
     * 
     * @param base64EncodedKey base64-encoded key
     * @return a base64 decoded byte array. Never {@literal null}.
     * @throws KeyException if there is an error decoding the string. 
     */
    @Nonnull private static byte[] base64DecodeOrThrow(@Nonnull final String base64EncodedKey) throws KeyException {
        try {
            return Base64.getMimeDecoder().decode(base64EncodedKey);
        } catch (final IllegalArgumentException e) {
            throw new KeyException("Unable to base64 decode key",e);
        }
    }

    /**
     * Build Java RSA private key from base64 encoding.
     * 
     * @param base64EncodedKey base64-encoded RSA private key
     * @return a native Java RSAPrivateKey
     * @throws KeyException thrown if there is an error constructing key
     */
    @Nonnull public static RSAPrivateKey buildJavaRSAPrivateKey(@Nonnull final String base64EncodedKey)
            throws KeyException {
        final PrivateKey key = buildJavaPrivateKey(base64EncodedKey);
        if (!(key instanceof RSAPrivateKey)) {
            throw new KeyException("Generated key was not an RSAPrivateKey instance");
        }
        return (RSAPrivateKey) key;
    }

    /**
     * Build Java DSA private key from base64 encoding.
     * 
     * @param base64EncodedKey base64-encoded DSA private key
     * @return a native Java DSAPrivateKey
     * @throws KeyException thrown if there is an error constructing key
     */
    @Nonnull public static DSAPrivateKey buildJavaDSAPrivateKey(@Nonnull final String base64EncodedKey)
            throws KeyException {
        final PrivateKey key = buildJavaPrivateKey(base64EncodedKey);
        if (!(key instanceof DSAPrivateKey)) {
            throw new KeyException("Generated key was not a DSAPrivateKey instance");
        }
        return (DSAPrivateKey) key;
    }

    /**
     * Build Java DH private key from base64 encoding.
     * 
     * @param base64EncodedKey base64-encoded DH private key
     * @return a native Java DHPrivateKey
     * @throws KeyException thrown if there is an error constructing key
     */
    @Nonnull public static DHPrivateKey buildJavaDHPrivateKey(@Nonnull final String base64EncodedKey)
            throws KeyException {
        final PrivateKey key = buildJavaPrivateKey(base64EncodedKey);
        if (!(key instanceof DHPrivateKey)) {
            throw new KeyException("Generated key was not a DHPrivateKey instance");
        }
        return (DHPrivateKey) key;
    }

    /**
     * Build Java EC private key from base64 encoding.
     * 
     * @param base64EncodedKey base64-encoded EC private key
     * @return a native Java ECPrivateKey
     * @throws KeyException thrown if there is an error constructing key
     */
    public static ECPrivateKey buildJavaECPrivateKey(final String base64EncodedKey)  throws KeyException {
        final PrivateKey key =  buildJavaPrivateKey(base64EncodedKey);
        if (! (key instanceof ECPrivateKey)) {
            throw new KeyException("Generated key was not an ECPrivateKey instance");
        }
        return (ECPrivateKey) key;
    }
    
    /**
     * Build Java private key from base64 encoding. The key should have no password.
     * 
     * @param base64EncodedKey base64-encoded private key
     * @return a native Java PrivateKey
     * @throws KeyException thrown if there is an error constructing key
     */
    @Nonnull public static PrivateKey buildJavaPrivateKey(@Nonnull final String base64EncodedKey) throws KeyException {
        return decodePrivateKey(base64DecodeOrThrow(base64EncodedKey), null);
    }

    /**
     * Generates a public key from the given key spec.
     * 
     * @param keySpec {@link KeySpec} specification for the key
     * @param keyAlgorithm key generation algorithm, only DSA, RSA, and EC supported
     * 
     * @return the generated {@link PublicKey}
     * 
     * @throws KeyException thrown if the key algorithm is not supported by the JCA or the key spec does not contain
     *             valid information
     */
    @Nonnull public static PublicKey buildKey(@Nullable final KeySpec keySpec, @Nonnull final String keyAlgorithm)
            throws KeyException {
        Constraint.isNotNull(keyAlgorithm, "Key algorithm cannot be null");
        
        try {
            final KeyFactory keyFactory = KeyFactory.getInstance(keyAlgorithm);
            return keyFactory.generatePublic(keySpec);
        } catch (final NoSuchAlgorithmException e) {
            throw new KeyException(keyAlgorithm + "algorithm is not supported by the JCA", e);
        } catch (final InvalidKeySpecException e) {
            throw new KeyException("Invalid key information", e);
        }
    }

    /**
     * Generate a random symmetric key.
     * 
     * @param algo key algorithm
     * @param keyLength key length
     * @param provider JCA provider
     * @return randomly generated symmetric key
     * @throws NoSuchAlgorithmException algorithm not found
     * @throws NoSuchProviderException provider not found
     */
    @Nonnull public static SecretKey generateKey(@Nonnull final String algo, final int keyLength,
            @Nullable final String provider) throws NoSuchAlgorithmException, NoSuchProviderException {
        Constraint.isNotNull(algo, "Key algorithm cannot be null");
        
        KeyGenerator keyGenerator = null;
        if (provider != null) {
            keyGenerator = KeyGenerator.getInstance(algo, provider);
        } else {
            keyGenerator = KeyGenerator.getInstance(algo);
        }
        keyGenerator.init(keyLength);
        return keyGenerator.generateKey();
    }

    /**
     * Generate a random symmetric key.
     * 
     * @param algo key algorithm
     * @param paramSpec the algorithm parameter specification
     * @param provider JCA provider
     * @return randomly generated symmetric key
     * @throws NoSuchAlgorithmException algorithm not found
     * @throws NoSuchProviderException provider not found
     * @throws InvalidAlgorithmParameterException invalid parameter specification
     */
    @Nonnull public static SecretKey generateKey(@Nonnull final String algo,
            @Nonnull final AlgorithmParameterSpec paramSpec, @Nullable final String provider)
                    throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        Constraint.isNotNull(algo, "Key algorithm cannot be null");
        Constraint.isNotNull(paramSpec, "Algorithm parameter spec cannot be null");
        
        KeyGenerator keyGenerator = null;
        if (provider != null) {
            keyGenerator = KeyGenerator.getInstance(algo, provider);
        } else {
            keyGenerator = KeyGenerator.getInstance(algo);
        }
        keyGenerator.init(paramSpec);
        return keyGenerator.generateKey();
    }

    /**
     * Generate a random asymmetric key pair.
     * 
     * @param algo key algorithm
     * @param keyLength key length
     * @param provider JCA provider
     * @return randomly generated key
     * @throws NoSuchAlgorithmException algorithm not found
     * @throws NoSuchProviderException provider not found
     */
    @Nonnull public static KeyPair generateKeyPair(@Nonnull final String algo, final int keyLength,
            @Nullable final String provider) throws NoSuchAlgorithmException, NoSuchProviderException {
        Constraint.isNotNull(algo, "Key algorithm cannot be null");
        
        KeyPairGenerator keyGenerator = null;
        if (provider != null) {
            keyGenerator = KeyPairGenerator.getInstance(algo, provider);
        } else {
            keyGenerator = KeyPairGenerator.getInstance(algo);
        }
        keyGenerator.initialize(keyLength);
        return keyGenerator.generateKeyPair();
    }

    /**
     * Generate a random asymmetric key pair.
     * 
     * @param algo key algorithm
     * @param paramSpec the algorithm parameter specification
     * @param provider JCA provider
     * @return randomly generated key
     * @throws NoSuchAlgorithmException algorithm not found
     * @throws NoSuchProviderException provider not found
     * @throws InvalidAlgorithmParameterException invalid parameter specification
     */
    @Nonnull public static KeyPair generateKeyPair(@Nonnull final String algo,
            @Nonnull final AlgorithmParameterSpec paramSpec, @Nullable final String provider)
                    throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        Constraint.isNotNull(algo, "Key algorithm cannot be null");
        
        KeyPairGenerator keyGenerator = null;
        if (provider != null) {
            keyGenerator = KeyPairGenerator.getInstance(algo, provider);
        } else {
            keyGenerator = KeyPairGenerator.getInstance(algo);
        }
        keyGenerator.initialize(paramSpec);
        return keyGenerator.generateKeyPair();
    }
    
    /**
     * Compare the supplied public and private keys, and determine if they correspond to the same key pair.
     * 
     * @param pubKey the public key
     * @param privKey the private key
     * @return true if the public and private are from the same key pair, false if not
     * @throws SecurityException if the keys can not be evaluated, or if the key algorithm is unsupported or unknown
     */
    public static boolean matchKeyPair(@Nonnull final PublicKey pubKey, @Nonnull final PrivateKey privKey)
            throws SecurityException {
        // This approach attempts to match the keys by signing and then validating some known data.
        if (pubKey == null || privKey == null) {
            throw new SecurityException("Either public or private key was null");
        }

        final String jcaAlgoID = keyMatchAlgorithms.get(privKey.getAlgorithm());
        if (jcaAlgoID == null) {
            throw new SecurityException("Can't determine JCA algorithm ID for key matching from key algorithm: "
                    + privKey.getAlgorithm());
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Attempting to match key pair containing key algorithms public '{}' private '{}', "
                    + "using JCA signature algorithm '{}'", new Object[] {pubKey.getAlgorithm(),
                    privKey.getAlgorithm(), jcaAlgoID,});
        }

        final byte[] data = "This is the data to sign".getBytes();
        final byte[] signature = SigningUtil.sign(privKey, jcaAlgoID, data);
        return SigningUtil.verify(pubKey, jcaAlgoID, signature, data);
    }

    static {
        keyMatchAlgorithms = new LazyMap<>();
        keyMatchAlgorithms.put(JCAConstants.KEY_ALGO_RSA, JCAConstants.SIGNATURE_RSA_SHA1);
        keyMatchAlgorithms.put(JCAConstants.KEY_ALGO_DSA, JCAConstants.SIGNATURE_DSA_SHA1);
        keyMatchAlgorithms.put(JCAConstants.KEY_ALGO_EC, JCAConstants.SIGNATURE_ECDSA_SHA1);
    }

}