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

import java.security.SecureRandom;
import java.util.HexFormat;

import javax.annotation.Nonnull;
import javax.crypto.SecretKey;

import org.opensaml.core.testing.XMLObjectBaseTestCase;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.xmlsec.algorithm.AlgorithmRegistry;
import org.opensaml.xmlsec.algorithm.AlgorithmSupport;
import org.opensaml.xmlsec.algorithm.BlockEncryptionAlgorithm;
import org.opensaml.xmlsec.derivation.KeyDerivationException;
import org.opensaml.xmlsec.encryption.IterationCount;
import org.opensaml.xmlsec.encryption.KeyDerivationMethod;
import org.opensaml.xmlsec.encryption.KeyLength;
import org.opensaml.xmlsec.encryption.PBKDF2Params;
import org.opensaml.xmlsec.encryption.PRF;
import org.opensaml.xmlsec.encryption.Salt;
import org.opensaml.xmlsec.encryption.Specified;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.google.common.base.Charsets;

import net.shibboleth.shared.codec.Base64Support;
import net.shibboleth.shared.codec.EncodingException;
import net.shibboleth.shared.component.ComponentInitializationException;

@SuppressWarnings({"javadoc", "null"})
public class PBKDF2Test extends XMLObjectBaseTestCase {
    
    @Test
    public void defaultProperties() throws Exception {
        PBKDF2 kdf = new PBKDF2();
        kdf.initialize();
        
        Assert.assertEquals(kdf.getAlgorithm(), EncryptionConstants.ALGO_ID_KEYDERIVATION_PBKDF2);
        
        Assert.assertEquals(kdf.getGeneratedSaltLength(), PBKDF2.DEFAULT_GENERATED_SALT_LENGTH);
        Assert.assertEquals(kdf.getIterationCount(), PBKDF2.DEFAULT_ITERATION_COUNT);
        Assert.assertNull(kdf.getKeyLength());
        Assert.assertEquals(kdf.getPRF(), PBKDF2.DEFAULT_PRF);
        Assert.assertNotNull(kdf.getRandom());
        Assert.assertNull(kdf.getSalt());
    }
    
    @Test
    public void explicitProperties() throws Exception {
        SecureRandom sr = new SecureRandom();
        
        PBKDF2 kdf = new PBKDF2();
        kdf.setGeneratedSaltLength(16);
        kdf.setIterationCount(3000);
        kdf.setKeyLength(256);
        kdf.setPRF(SignatureConstants.ALGO_ID_MAC_HMAC_SHA512);
        kdf.setRandom(sr);
        kdf.setSalt("ABCD");
        kdf.initialize();
        
        Assert.assertEquals(kdf.getAlgorithm(), EncryptionConstants.ALGO_ID_KEYDERIVATION_PBKDF2);
        
        Assert.assertEquals(kdf.getGeneratedSaltLength(), 16);
        Assert.assertEquals(kdf.getIterationCount(), 3000);
        Assert.assertEquals(kdf.getKeyLength(), 256);
        Assert.assertEquals(kdf.getPRF(), SignatureConstants.ALGO_ID_MAC_HMAC_SHA512);
        Assert.assertSame(kdf.getRandom(), sr);
        Assert.assertEquals(kdf.getSalt(), "ABCD");
    }
    
    @Test(expectedExceptions = ComponentInitializationException.class)
    public void initBadSalt() throws Exception {
        PBKDF2 kdf = new PBKDF2();
        kdf.setSalt("INVALID BASE64");
        kdf.initialize();
    }
    
    @Test(expectedExceptions = ComponentInitializationException.class)
    public void initBadKeyLength() throws Exception {
        PBKDF2 kdf = new PBKDF2();
        kdf.setKeyLength(129);
        kdf.initialize();
    }
    
    @Test(expectedExceptions = ComponentInitializationException.class)
    public void initBadPRF() throws Exception {
        PBKDF2 kdf = new PBKDF2();
        kdf.setPRF(EncryptionConstants.ALGO_ID_DIGEST_SHA256);
        kdf.initialize();
    }
    
    @Test
    public void xmlGenerationSuccess() throws Exception {
        PBKDF2 kdf = new PBKDF2();
        kdf.setIterationCount(3000);
        kdf.setKeyLength(256);
        kdf.setPRF(SignatureConstants.ALGO_ID_MAC_HMAC_SHA512);
        kdf.setSalt("ABCD");
        kdf.initialize();
        
        XMLObject xmlObject = kdf.buildXMLObject();
        Assert.assertNotNull(xmlObject);
        Assert.assertTrue(KeyDerivationMethod.class.isInstance(xmlObject));
        
        KeyDerivationMethod kdm = KeyDerivationMethod.class.cast(xmlObject);
        Assert.assertEquals(kdm.getAlgorithm(), EncryptionConstants.ALGO_ID_KEYDERIVATION_PBKDF2);
        Assert.assertEquals(kdm.getUnknownXMLObjects().size(), 1);
        
        PBKDF2Params kdmParams = PBKDF2Params.class.cast(kdm.getUnknownXMLObjects().get(0));
        
        final IterationCount icount = kdmParams.getIterationCount();
        assert icount != null;
        Assert.assertEquals(icount.getValue(), 3000);
        
        final KeyLength klen = kdmParams.getKeyLength();
        assert klen != null;
        Assert.assertEquals(klen.getValue(), 32); // bytes = 256/8
        
        final PRF prf = kdmParams.getPRF();
        assert prf != null;
        Assert.assertEquals(prf.getAlgorithm(), SignatureConstants.ALGO_ID_MAC_HMAC_SHA512);
        
        final Salt salt = kdmParams.getSalt();
        assert salt != null;
        final Specified spec = salt.getSpecified();
        assert spec != null;
        Assert.assertEquals(spec.getValue(), "ABCD");
    }
    
    @Test
    public void fromXMLObject() throws Exception {
        KeyDerivationMethod xmlKDM = buildXMLObject(KeyDerivationMethod.DEFAULT_ELEMENT_NAME);
        xmlKDM.setAlgorithm(EncryptionConstants.ALGO_ID_KEYDERIVATION_PBKDF2);
        
        PBKDF2Params xmlParams= buildXMLObject(PBKDF2Params.DEFAULT_ELEMENT_NAME);
        xmlKDM.getUnknownXMLObjects().add(xmlParams);
        
        IterationCount xmlIterationCount = buildXMLObject(IterationCount.DEFAULT_ELEMENT_NAME);
        xmlIterationCount.setValue(3000);
        xmlParams.setIterationCount(xmlIterationCount);
        
        KeyLength xmlKeyLength = buildXMLObject(KeyLength.DEFAULT_ELEMENT_NAME);
        xmlKeyLength.setValue(16);
        xmlParams.setKeyLength(xmlKeyLength);
        
        PRF xmlPRF = buildXMLObject(PRF.DEFAULT_ELEMENT_NAME);
        xmlPRF.setAlgorithm(SignatureConstants.ALGO_ID_MAC_HMAC_SHA256);
        xmlParams.setPRF(xmlPRF);
        
        Salt xmlSalt = buildXMLObject(Salt.DEFAULT_ELEMENT_NAME);
        Specified xmlSpecified = buildXMLObject(Specified.DEFAULT_ELEMENT_NAME);
        xmlSpecified.setValue("ABCD");
        xmlSalt.setSpecified(xmlSpecified);
        xmlParams.setSalt(xmlSalt);
        
        PBKDF2 parameter = PBKDF2.fromXMLObject(xmlKDM);
        Assert.assertNotNull(parameter);
        Assert.assertTrue(parameter.isInitialized());
        
        Assert.assertEquals(parameter.getIterationCount(), 3000);
        Assert.assertEquals(parameter.getKeyLength(), 128);
        Assert.assertEquals(parameter.getPRF(), SignatureConstants.ALGO_ID_MAC_HMAC_SHA256);
        Assert.assertEquals(parameter.getSalt(), "ABCD");
        
        KeyDerivationMethod xmlKDMBad = null;
        PBKDF2Params xmlParamsBad = null;
        
        xmlKDMBad = XMLObjectSupport.cloneXMLObject(xmlKDM);
        xmlKDMBad.setAlgorithm(EncryptionConstants.ALGO_ID_KEYDERIVATION_CONCATKDF);
        try {
            PBKDF2.fromXMLObject(xmlKDMBad);
            Assert.fail("Should have failed invalid XMLObject");
        } catch (ComponentInitializationException e) {
            //expected
        }
        
        xmlKDMBad = XMLObjectSupport.cloneXMLObject(xmlKDM);
        xmlKDMBad.getUnknownXMLObjects().add(buildXMLObject(simpleXMLObjectQName));
        try {
            PBKDF2.fromXMLObject(xmlKDMBad);
            Assert.fail("Should have failed invalid XMLObject");
        } catch (ComponentInitializationException e) {
            //expected
        }
        
        xmlKDMBad = XMLObjectSupport.cloneXMLObject(xmlKDM);
        xmlParamsBad = (PBKDF2Params) xmlKDMBad.getUnknownXMLObjects(PBKDF2Params.DEFAULT_ELEMENT_NAME).get(0);
        xmlParamsBad.setIterationCount(null);
        try {
            PBKDF2.fromXMLObject(xmlKDMBad);
            Assert.fail("Should have failed invalid XMLObject");
        } catch (ComponentInitializationException e) {
            //expected
        }
        
        xmlKDMBad = XMLObjectSupport.cloneXMLObject(xmlKDM);
        xmlParamsBad = (PBKDF2Params) xmlKDMBad.getUnknownXMLObjects(PBKDF2Params.DEFAULT_ELEMENT_NAME).get(0);
        xmlParamsBad.setKeyLength(null);
        try {
            PBKDF2.fromXMLObject(xmlKDMBad);
            Assert.fail("Should have failed invalid XMLObject");
        } catch (ComponentInitializationException e) {
            //expected
        }
        
        xmlKDMBad = XMLObjectSupport.cloneXMLObject(xmlKDM);
        xmlParamsBad = (PBKDF2Params) xmlKDMBad.getUnknownXMLObjects(PBKDF2Params.DEFAULT_ELEMENT_NAME).get(0);
        xmlParamsBad.setPRF(null);
        try {
            PBKDF2.fromXMLObject(xmlKDMBad);
            Assert.fail("Should have failed invalid XMLObject");
        } catch (ComponentInitializationException e) {
            //expected
        }
        
        xmlKDMBad = XMLObjectSupport.cloneXMLObject(xmlKDM);
        xmlParamsBad = (PBKDF2Params) xmlKDMBad.getUnknownXMLObjects(PBKDF2Params.DEFAULT_ELEMENT_NAME).get(0);
        xmlParamsBad.setSalt(null);
        try {
            PBKDF2.fromXMLObject(xmlKDMBad);
            Assert.fail("Should have failed invalid XMLObject");
        } catch (ComponentInitializationException e) {
            //expected
        }
    }
    
    @Test
    public void cloning() throws Exception {
        SecureRandom sr = new SecureRandom();
        
        PBKDF2 kdf = new PBKDF2();
        kdf.setGeneratedSaltLength(16);
        kdf.setIterationCount(3000);
        kdf.setKeyLength(256);
        kdf.setPRF(SignatureConstants.ALGO_ID_MAC_HMAC_SHA512);
        kdf.setRandom(sr);
        kdf.setSalt("ABCD");
        kdf.initialize();
        
        PBKDF2 cloned = kdf.clone();
        Assert.assertNotSame(cloned, kdf);
        
        Assert.assertNotNull(cloned);
        Assert.assertEquals(cloned.getGeneratedSaltLength(), 16);
        Assert.assertEquals(cloned.getIterationCount(), 3000);
        Assert.assertEquals(cloned.getKeyLength(), 256);
        Assert.assertEquals(cloned.getPRF(), SignatureConstants.ALGO_ID_MAC_HMAC_SHA512);
        Assert.assertSame(cloned.getRandom(), sr);
        Assert.assertEquals(cloned.getSalt(), "ABCD");
    }
    
    @Test
    public void deriveWithDefaults() throws Exception {
        PBKDF2 kdf = new PBKDF2();
        kdf.initialize();
        
        byte[] secret = HexFormat.of().parseHex("DEADBEEF");
        
        SecretKey derivedKey = kdf.derive(secret, EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128_GCM, null);
        
        Assert.assertNotNull(derivedKey);
        Assert.assertEquals(derivedKey.getAlgorithm(), "AES");
        Assert.assertEquals(derivedKey.getEncoded().length * 8, 128);
        
        // Salt and key length were dynamically generated, so sanity check the new property values
        final String salt = kdf.getSalt();
        assert salt != null;
        Assert.assertEquals(Base64Support.decode(salt).length, kdf.getGeneratedSaltLength());
        
        Assert.assertNotNull(kdf.getKeyLength());
        Assert.assertEquals(kdf.getKeyLength(), 128);
        
    }
    
    @Test
    public void deriveWithExplicitProperties() throws Exception {
        PBKDF2 kdf = new PBKDF2();
        kdf.setIterationCount(3000);
        kdf.setKeyLength(256);
        kdf.setPRF(SignatureConstants.ALGO_ID_MAC_HMAC_SHA512);
        kdf.setSalt("ABCD");
        kdf.initialize();
        
        byte[] secret = HexFormat.of().parseHex("DEADBEEF");
        
        SecretKey derivedKey = kdf.derive(secret, EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256_GCM, null);
        
        Assert.assertNotNull(derivedKey);
        Assert.assertEquals(derivedKey.getAlgorithm(), "AES");
        Assert.assertEquals(derivedKey.getEncoded().length * 8, 256);
    }
    
    @Test(expectedExceptions = KeyDerivationException.class)
    public void deriveWithKeyLengthMismatch() throws Exception {
        PBKDF2 kdf = new PBKDF2();
        kdf.setKeyLength(256);
        kdf.initialize();
        
        byte[] secret = HexFormat.of().parseHex("DEADBEEF");
        
        kdf.derive(secret, EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128_GCM, null);
    }
    
    @Test(expectedExceptions = KeyDerivationException.class)
    public void unknownKeyAlgorithm() throws Exception {
        PBKDF2 kdf = new PBKDF2();
        kdf.initialize();
        
        byte[] secret = HexFormat.of().parseHex("DEADBEEF");
        
        kdf.derive(secret, "urn:test:InvalidKeyAlgorithm", null);
    }

    @Test(expectedExceptions = KeyDerivationException.class)
    public void nonKeyLengthAlgorithm() throws Exception {
        PBKDF2 kdf = new PBKDF2();
        kdf.initialize();
        
        byte[] secret = HexFormat.of().parseHex("DEADBEEF");
        
        // Just use this as a stand-in for something which is KeySpecifiedAlgorithm but not KeyLengthSpecifiedAlgorithm
        kdf.derive(secret, SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256, null);
    }
    
    @Test
    public void nonKeyLengthAlgorithmWithSpecifiedLength() throws Exception {
        PBKDF2 kdf = new PBKDF2();
        kdf.initialize();
        
        byte[] secret = HexFormat.of().parseHex("DEADBEEF");
        
        // Just use this as a stand-in for something which is KeySpecifiedAlgorithm but not KeyLengthSpecifiedAlgorithm
        SecretKey derivedKey = kdf.derive(secret, SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256, 256);
        
        // This is bogus obviously, but just need to test that a known algo URI that is non-key length works with specified key length
        Assert.assertNotNull(derivedKey);
        Assert.assertEquals(derivedKey.getAlgorithm(), "RSA");
        Assert.assertEquals(derivedKey.getEncoded().length * 8, 256);
    }
    
    
    //
    // Derivation tests using test vectors from external sources, and supporting code
    //
    
    @BeforeClass
    public void setupTestVectorAlgorithms() {
        final AlgorithmRegistry registry = AlgorithmSupport.ensureGlobalAlgorithmRegistry();
        registry.register(new MockKeyAlgorithm128());
        registry.register(new MockKeyAlgorithm160());
        registry.register(new MockKeyAlgorithm200());
        registry.register(new MockKeyAlgorithm256());
        registry.register(new MockKeyAlgorithm320());
    }
    
    @AfterClass
    public void teardownTestVectorAlgorithms() {
        final AlgorithmRegistry registry = AlgorithmSupport.ensureGlobalAlgorithmRegistry();
        registry.deregister(new MockKeyAlgorithm128());
        registry.deregister(new MockKeyAlgorithm160());
        registry.deregister(new MockKeyAlgorithm200());
        registry.register(new MockKeyAlgorithm256());
        registry.deregister(new MockKeyAlgorithm320());
    }
    
    private String whitespace(String input) { 
        return input.replaceAll("\\s", "");
    }

    @DataProvider(name = "testVectors")
    public Object[][] testVectors() throws EncodingException {
        return new Object[][] {
            // RFC 6070: https://tools.ietf.org/html/rfc6070
            // These are older and use SHA-1-based PRF.
            new Object[] {
                    "password".getBytes(Charsets.UTF_8),
                    "urn:test:MockKeyAlgorithm:160",
                    SignatureConstants.ALGO_ID_MAC_HMAC_SHA1,
                    Base64Support.encode("salt".getBytes(Charsets.UTF_8), false),
                    1,
                    HexFormat.of().parseHex(whitespace("0c 60 c8 0f 96 1f 0e 71" +
                                             "f3 a9 b5 24 af 60 12 06" +
                                             "2f e0 37 a6"))},
            
            new Object[] {
                    "password".getBytes(Charsets.UTF_8),
                    "urn:test:MockKeyAlgorithm:160",
                    SignatureConstants.ALGO_ID_MAC_HMAC_SHA1,
                    Base64Support.encode("salt".getBytes(Charsets.UTF_8), false),
                    2,
                    HexFormat.of().parseHex(whitespace("ea 6c 01 4d c7 2d 6f 8c" + 
                                             "cd 1e d9 2a ce 1d 41 f0" +
                                             "d8 de 89 57"))},
            
            new Object[] {
                    "password".getBytes(Charsets.UTF_8),
                    "urn:test:MockKeyAlgorithm:160",
                    SignatureConstants.ALGO_ID_MAC_HMAC_SHA1,
                    Base64Support.encode("salt".getBytes(Charsets.UTF_8), false),
                    4096,
                    HexFormat.of().parseHex(whitespace("4b 00 79 01 b7 65 48 9a" + 
                                             "be ad 49 d9 26 f7 21 d0" + 
                                             "65 a4 29 c1  "))},
            
            /* This takes a couple of minutes, so don't run in automated tests, etc.
            new Object[] {
                    "password".getBytes(Charsets.UTF_8),
                    "urn:test:MockKeyAlgorithm:160",
                    SignatureConstants.ALGO_ID_MAC_HMAC_SHA1,
                    Base64Support.encode("salt".getBytes(Charsets.UTF_8), false),
                    16777216,
                    HexFormat.of().parseHex(whitespace("ee fe 3d 61 cd 4d a4 e4" + 
                                             "e9 94 5b 3d 6b a2 15 8c" + 
                                             "26 34 e9 84 "))},
             */
            
            new Object[] {
                    "passwordPASSWORDpassword".getBytes(Charsets.UTF_8),
                    "urn:test:MockKeyAlgorithm:200",
                    SignatureConstants.ALGO_ID_MAC_HMAC_SHA1,
                    Base64Support.encode("saltSALTsaltSALTsaltSALTsaltSALTsalt".getBytes(Charsets.UTF_8), false),
                    4096,
                    HexFormat.of().parseHex(whitespace("3d 2e ec 4f e4 1c 84 9b" + 
                                             "80 c8 d8 36 62 c0 e4 4a" + 
                                             "8b 29 1a 96 4c f2 f0 70" + 
                                             "38"))},
            
            new Object[] {
                    // These are testing a literal ASCII NULL (0x00) in the secret and salt
                    "pass\u0000word".getBytes(Charsets.UTF_8),
                    "urn:test:MockKeyAlgorithm:128",
                    SignatureConstants.ALGO_ID_MAC_HMAC_SHA1,
                    Base64Support.encode("sa\u0000lt".getBytes(Charsets.UTF_8), false),
                    4096,
                    HexFormat.of().parseHex(whitespace("56 fa 6a a7 55 48 09 9d" + 
                                             "cc 37 d7 f0 34 25 e0 c3"))},
            
            
            // Non-normative vectors for SHA-2 PRF.
            // https://stackoverflow.com/questions/5130513/pbkdf2-hmac-sha2-test-vectors/5136918#5136918
            new Object[] {
                    "password".getBytes(Charsets.UTF_8),
                    "urn:test:MockKeyAlgorithm:256",
                    SignatureConstants.ALGO_ID_MAC_HMAC_SHA256,
                    Base64Support.encode("salt".getBytes(Charsets.UTF_8), false),
                    1,
                    HexFormat.of().parseHex(whitespace("12 0f b6 cf fc f8 b3 2c" + 
                                             "43 e7 22 52 56 c4 f8 37" + 
                                             "a8 65 48 c9 2c cc 35 48" + 
                                             "08 05 98 7c b7 0b e1 7b"))},
            
            new Object[] {
                    "password".getBytes(Charsets.UTF_8),
                    "urn:test:MockKeyAlgorithm:256",
                    SignatureConstants.ALGO_ID_MAC_HMAC_SHA256,
                    Base64Support.encode("salt".getBytes(Charsets.UTF_8), false),
                    2,
                    HexFormat.of().parseHex(whitespace("ae 4d 0c 95 af 6b 46 d3" + 
                                             "2d 0a df f9 28 f0 6d d0" + 
                                             "2a 30 3f 8e f3 c2 51 df" + 
                                             "d6 e2 d8 5a 95 47 4c 43"))},
            
            new Object[] {
                    "password".getBytes(Charsets.UTF_8),
                    "urn:test:MockKeyAlgorithm:256",
                    SignatureConstants.ALGO_ID_MAC_HMAC_SHA256,
                    Base64Support.encode("salt".getBytes(Charsets.UTF_8), false),
                    4096,
                    HexFormat.of().parseHex(whitespace("c5 e4 78 d5 92 88 c8 41" + 
                                             "aa 53 0d b6 84 5c 4c 8d" + 
                                             "96 28 93 a0 01 ce 4e 11" + 
                                             "a4 96 38 73 aa 98 13 4a"))},
            
            /* This takes a couple of minutes, so don't run in automated tests, etc.
            new Object[] {
                    "password".getBytes(Charsets.UTF_8),
                    "urn:test:MockKeyAlgorithm:256",
                    SignatureConstants.ALGO_ID_MAC_HMAC_SHA256,
                    Base64Support.encode("salt".getBytes(Charsets.UTF_8), false),
                    16777216,
                    HexFormat.of().parseHex(whitespace("cf 81 c6 6f e8 cf c0 4d" + 
                                             "1f 31 ec b6 5d ab 40 89" + 
                                             "f7 f1 79 e8 9b 3b 0b cb" + 
                                             "17 ad 10 e3 ac 6e ba 46"))},
             */
            
            new Object[] {
                    "passwordPASSWORDpassword".getBytes(Charsets.UTF_8),
                    "urn:test:MockKeyAlgorithm:320",
                    SignatureConstants.ALGO_ID_MAC_HMAC_SHA256,
                    Base64Support.encode("saltSALTsaltSALTsaltSALTsaltSALTsalt".getBytes(Charsets.UTF_8), false),
                    4096,
                    HexFormat.of().parseHex(whitespace("34 8c 89 db cb d3 2b 2f" + 
                                             "32 d8 14 b8 11 6e 84 cf" + 
                                             "2b 17 34 7e bc 18 00 18" + 
                                             "1c 4e 2a 1f b8 dd 53 e1" + 
                                             "c6 35 51 8c 7d ac 47 e9"))},
            
            new Object[] {
                    // These are testing a literal ASCII NULL (0x00) in the secret and salt
                    "pass\u0000word".getBytes(Charsets.UTF_8),
                    "urn:test:MockKeyAlgorithm:128",
                    SignatureConstants.ALGO_ID_MAC_HMAC_SHA256,
                    Base64Support.encode("sa\u0000lt".getBytes(Charsets.UTF_8), false),
                    4096,
                    HexFormat.of().parseHex(whitespace("89 b6 9d 05 16 f8 29 89" + 
                                             "3c 69 62 26 65 0a 86 87"))},
            
        };
    }
    
    @Test(dataProvider = "testVectors")
    public void deriveTestVectors(byte[] secret, String keyAlgorithm, String prfAlgorithm, String salt, Integer iterationCount,
            byte[] keyBytes) throws Exception {
        
        String jcaKeyAlgorithm = AlgorithmSupport.getKeyAlgorithm(keyAlgorithm);
        Assert.assertNotNull(jcaKeyAlgorithm);
        Integer jcaKeyLength = AlgorithmSupport.getKeyLength(keyAlgorithm);
        Assert.assertNotNull(jcaKeyLength);
        
        PBKDF2 kdf = new PBKDF2();
        kdf.setIterationCount(iterationCount);
        kdf.setKeyLength(jcaKeyLength);
        kdf.setPRF(prfAlgorithm);
        kdf.setSalt(salt);
        kdf.initialize();
        
        SecretKey derivedKey = kdf.derive(secret, keyAlgorithm, null);
        
        Assert.assertNotNull(derivedKey);
        Assert.assertEquals(derivedKey.getAlgorithm(), jcaKeyAlgorithm);
        Assert.assertEquals(derivedKey.getEncoded().length * 8, jcaKeyLength);
        Assert.assertEquals(derivedKey.getEncoded(), keyBytes);
    }
    
    // Mock key algorithm descriptors for test vectors
    
    private class MockKeyAlgorithm128 implements BlockEncryptionAlgorithm {

        /** {@inheritDoc} */
        @Nonnull public String getKey() {
            return "MockKey";
        }

        /** {@inheritDoc} */
        @Nonnull public String getURI() {
            return "urn:test:MockKeyAlgorithm:128";
        }

        /** {@inheritDoc} */
        public int getKeyLength() {
            // 16 bytes
            return 128;
        }

        /** {@inheritDoc} */
        @Nonnull public AlgorithmType getType() {
            return AlgorithmType.BlockEncryption;
        }

        /** {@inheritDoc} */
        @Nonnull public String getJCAAlgorithmID() {
            throw new UnsupportedOperationException();
        }

        /** {@inheritDoc} */
        @Nonnull public String getCipherMode() {
            throw new UnsupportedOperationException();
        }

        /** {@inheritDoc} */
        @Nonnull public String getPadding() {
            throw new UnsupportedOperationException();
        }
        
    }
    
    private class MockKeyAlgorithm160 implements BlockEncryptionAlgorithm {

        /** {@inheritDoc} */
        @Nonnull public String getKey() {
            return "MockKey";
        }

        /** {@inheritDoc} */
        @Nonnull public String getURI() {
            return "urn:test:MockKeyAlgorithm:160";
        }

        /** {@inheritDoc} */
        public int getKeyLength() {
            // 20 bytes
            return 160;
        }

        /** {@inheritDoc} */
        @Nonnull public AlgorithmType getType() {
            return AlgorithmType.BlockEncryption;
        }

        /** {@inheritDoc} */
        @Nonnull public String getJCAAlgorithmID() {
            throw new UnsupportedOperationException();
        }

        /** {@inheritDoc} */
        @Nonnull public String getCipherMode() {
            throw new UnsupportedOperationException();
        }

        /** {@inheritDoc} */
        @Nonnull public String getPadding() {
            throw new UnsupportedOperationException();
        }
        
    }
    
    private class MockKeyAlgorithm200 implements BlockEncryptionAlgorithm {

        /** {@inheritDoc} */
        @Nonnull public String getKey() {
            return "MockKey";
        }

        /** {@inheritDoc} */
        @Nonnull public String getURI() {
            return "urn:test:MockKeyAlgorithm:200";
        }

        /** {@inheritDoc} */
        public int getKeyLength() {
            // 25 bytes
            return 200;
        }

        /** {@inheritDoc} */
        @Nonnull public AlgorithmType getType() {
            return AlgorithmType.BlockEncryption;
        }

        /** {@inheritDoc} */
        @Nonnull public String getJCAAlgorithmID() {
            throw new UnsupportedOperationException();
        }

        /** {@inheritDoc} */
        @Nonnull public String getCipherMode() {
            throw new UnsupportedOperationException();
        }

        /** {@inheritDoc} */
        @Nonnull public String getPadding() {
            throw new UnsupportedOperationException();
        }
        
    }
    
    private class MockKeyAlgorithm256 implements BlockEncryptionAlgorithm {

        /** {@inheritDoc} */
        @Nonnull public String getKey() {
            return "MockKey";
        }

        /** {@inheritDoc} */
        @Nonnull public String getURI() {
            return "urn:test:MockKeyAlgorithm:256";
        }

        /** {@inheritDoc} */
        public int getKeyLength() {
            // 32 bytes
            return 256;
        }

        /** {@inheritDoc} */
        @Nonnull public AlgorithmType getType() {
            return AlgorithmType.BlockEncryption;
        }

        /** {@inheritDoc} */
        @Nonnull public String getJCAAlgorithmID() {
            throw new UnsupportedOperationException();
        }

        /** {@inheritDoc} */
        @Nonnull public String getCipherMode() {
            throw new UnsupportedOperationException();
        }

        /** {@inheritDoc} */
        @Nonnull public String getPadding() {
            throw new UnsupportedOperationException();
        }
        
    }
    
    private class MockKeyAlgorithm320 implements BlockEncryptionAlgorithm {

        /** {@inheritDoc} */
        @Nonnull public String getKey() {
            return "MockKey";
        }

        /** {@inheritDoc} */
        @Nonnull public String getURI() {
            return "urn:test:MockKeyAlgorithm:320";
        }

        /** {@inheritDoc} */
        public int getKeyLength() {
            // 40 bytes
            return 320;
        }

        /** {@inheritDoc} */
        @Nonnull public AlgorithmType getType() {
            return AlgorithmType.BlockEncryption;
        }

        /** {@inheritDoc} */
        @Nonnull public String getJCAAlgorithmID() {
            throw new UnsupportedOperationException();
        }

        /** {@inheritDoc} */
        @Nonnull public String getCipherMode() {
            throw new UnsupportedOperationException();
        }

        /** {@inheritDoc} */
        @Nonnull public String getPadding() {
            throw new UnsupportedOperationException();
        }
        
    }
    
}