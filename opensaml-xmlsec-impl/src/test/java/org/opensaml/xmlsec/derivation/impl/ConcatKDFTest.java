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

import javax.crypto.SecretKey;

import org.opensaml.core.testing.XMLObjectBaseTestCase;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.xmlsec.derivation.KeyDerivationException;
import org.opensaml.xmlsec.encryption.ConcatKDFParams;
import org.opensaml.xmlsec.encryption.KeyDerivationMethod;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.signature.DigestMethod;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import net.shibboleth.shared.codec.EncodingException;
import net.shibboleth.shared.component.ComponentInitializationException;

@SuppressWarnings({"javadoc", "null"})
public class ConcatKDFTest extends XMLObjectBaseTestCase {
    
    @Test
    public void defaultProperties() throws Exception {
        ConcatKDF kdf = new ConcatKDF();
        kdf.initialize();
        
        Assert.assertEquals(kdf.getAlgorithm(), EncryptionConstants.ALGO_ID_KEYDERIVATION_CONCATKDF);
        
        Assert.assertNull(kdf.getAlgorithmID());
        Assert.assertNull(kdf.getPartyUInfo());
        Assert.assertNull(kdf.getPartyVInfo());
        Assert.assertNull(kdf.getSuppPubInfo());
        Assert.assertNull(kdf.getSuppPrivInfo());
        Assert.assertEquals(kdf.getDigestMethod(), SignatureConstants.ALGO_ID_DIGEST_SHA256);
    }

    @Test
    public void explicitProperties() throws Exception {
        ConcatKDF kdf = new ConcatKDF();
        kdf.setAlgorithmID("  AA  ");
        kdf.setPartyUInfo("  BB  ");
        kdf.setPartyVInfo("  CC  ");
        kdf.setSuppPubInfo("  DD  ");
        kdf.setSuppPrivInfo("  EE  ");
        kdf.setDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA512);
        kdf.initialize();
        
        Assert.assertEquals(kdf.getAlgorithm(), EncryptionConstants.ALGO_ID_KEYDERIVATION_CONCATKDF);
        
        Assert.assertEquals(kdf.getAlgorithmID(), "AA");
        Assert.assertEquals(kdf.getPartyUInfo(), "BB");
        Assert.assertEquals(kdf.getPartyVInfo(), "CC");
        Assert.assertEquals(kdf.getSuppPubInfo(), "DD");
        Assert.assertEquals(kdf.getSuppPrivInfo(), "EE");
        Assert.assertEquals(kdf.getDigestMethod(), SignatureConstants.ALGO_ID_DIGEST_SHA512);
    }
    
    @Test(expectedExceptions = ComponentInitializationException.class)
    public void initNonDigestMethod() throws Exception {
        ConcatKDF kdf = new ConcatKDF();
        kdf.setDigestMethod(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
        kdf.initialize();
    }

    @Test(expectedExceptions = ComponentInitializationException.class)
    public void initUnsupportedDigest() throws Exception {
        ConcatKDF kdf = new ConcatKDF();
        kdf.setDigestMethod(SignatureConstants.ALGO_ID_DIGEST_NOT_RECOMMENDED_MD5);
        kdf.initialize();
    }
    
    @Test(expectedExceptions = ComponentInitializationException.class)
    public void initBadAlgorithmID() throws Exception {
        ConcatKDF kdf = new ConcatKDF();
        kdf.setAlgorithmID("INVALID");
        kdf.initialize();
    }

    @Test(expectedExceptions = ComponentInitializationException.class)
    public void initBadPartyUInfo() throws Exception {
        ConcatKDF kdf = new ConcatKDF();
        kdf.setPartyUInfo("INVALID");
        kdf.initialize();
    }

    @Test(expectedExceptions = ComponentInitializationException.class)
    public void initBadPartyVInfo() throws Exception {
        ConcatKDF kdf = new ConcatKDF();
        kdf.setPartyVInfo("INVALID");
        kdf.initialize();
    }

    @Test(expectedExceptions = ComponentInitializationException.class)
    public void initBadSuppPubInfo() throws Exception {
        ConcatKDF kdf = new ConcatKDF();
        kdf.setSuppPubInfo("INVALID");
        kdf.initialize();
    }

    @Test(expectedExceptions = ComponentInitializationException.class)
    public void initBadSuppPrivInfo() throws Exception {
        ConcatKDF kdf = new ConcatKDF();
        kdf.setSuppPrivInfo("INVALID");
        kdf.initialize();
    }

    @Test
    public void xmlGenerationSuccess() throws Exception {
        ConcatKDF kdf = new ConcatKDF();
        kdf.setAlgorithmID("AA");
        kdf.setPartyUInfo("BB");
        kdf.setPartyVInfo("CC");
        kdf.setSuppPubInfo("DD");
        kdf.setSuppPrivInfo("EE");
        kdf.setDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA512);
        kdf.initialize();
        
        XMLObject xmlObject = kdf.buildXMLObject();
        Assert.assertNotNull(xmlObject);
        Assert.assertTrue(KeyDerivationMethod.class.isInstance(xmlObject));
        
        KeyDerivationMethod kdm = KeyDerivationMethod.class.cast(xmlObject);
        Assert.assertEquals(kdm.getAlgorithm(), EncryptionConstants.ALGO_ID_KEYDERIVATION_CONCATKDF);
        Assert.assertEquals(kdm.getUnknownXMLObjects().size(), 1);
        
        ConcatKDFParams kdmParams = ConcatKDFParams.class.cast(kdm.getUnknownXMLObjects().get(0));
        
        Assert.assertEquals(kdmParams.getAlgorithmID(), "00AA");
        Assert.assertEquals(kdmParams.getPartyUInfo(), "00BB");
        Assert.assertEquals(kdmParams.getPartyVInfo(), "00CC");
        Assert.assertEquals(kdmParams.getSuppPubInfo(), "00DD");
        Assert.assertEquals(kdmParams.getSuppPrivInfo(), "00EE");
        
        final DigestMethod method = kdmParams.getDigestMethod();
        assert method != null;
        Assert.assertEquals(method.getAlgorithm(), SignatureConstants.ALGO_ID_DIGEST_SHA512);
    }
    
    @Test
    public void fromXMLObject_Basic() throws Exception {
        KeyDerivationMethod xmlKDM = buildXMLObject(KeyDerivationMethod.DEFAULT_ELEMENT_NAME);
        xmlKDM.setAlgorithm(EncryptionConstants.ALGO_ID_KEYDERIVATION_CONCATKDF);
        
        ConcatKDFParams xmlParams= buildXMLObject(ConcatKDFParams.DEFAULT_ELEMENT_NAME);
        xmlKDM.getUnknownXMLObjects().add(xmlParams);
        
        DigestMethod xmlDigest = buildXMLObject(DigestMethod.DEFAULT_ELEMENT_NAME);
        xmlDigest.setAlgorithm(SignatureConstants.ALGO_ID_DIGEST_SHA256);
        xmlParams.setDigestMethod(xmlDigest);
        
        xmlParams.setAlgorithmID("00AA");
        xmlParams.setPartyUInfo("00BB");
        xmlParams.setPartyVInfo("00CC");
        xmlParams.setSuppPubInfo("00DD");
        xmlParams.setSuppPrivInfo("00EE");
        
        ConcatKDF parameter = ConcatKDF.fromXMLObject(xmlKDM);
        Assert.assertNotNull(parameter);
        Assert.assertTrue(parameter.isInitialized());

        Assert.assertEquals(parameter.getAlgorithm(), EncryptionConstants.ALGO_ID_KEYDERIVATION_CONCATKDF);
        Assert.assertEquals(parameter.getDigestMethod(), SignatureConstants.ALGO_ID_DIGEST_SHA256);

        Assert.assertEquals(parameter.getAlgorithmID(), "AA");
        Assert.assertEquals(parameter.getPartyUInfo(), "BB");
        Assert.assertEquals(parameter.getPartyVInfo(), "CC");
        Assert.assertEquals(parameter.getSuppPubInfo(), "DD");
        Assert.assertEquals(parameter.getSuppPrivInfo(), "EE");
    }
    
    @Test
    public void fromXMLObject_NullBitstrings() throws Exception {
        KeyDerivationMethod xmlKDM = buildXMLObject(KeyDerivationMethod.DEFAULT_ELEMENT_NAME);
        xmlKDM.setAlgorithm(EncryptionConstants.ALGO_ID_KEYDERIVATION_CONCATKDF);
        
        ConcatKDFParams xmlParams= buildXMLObject(ConcatKDFParams.DEFAULT_ELEMENT_NAME);
        xmlKDM.getUnknownXMLObjects().add(xmlParams);
        
        DigestMethod xmlDigest = buildXMLObject(DigestMethod.DEFAULT_ELEMENT_NAME);
        xmlDigest.setAlgorithm(SignatureConstants.ALGO_ID_DIGEST_SHA256);
        xmlParams.setDigestMethod(xmlDigest);
        
        xmlParams.setAlgorithmID(null);
        xmlParams.setPartyUInfo(null);
        xmlParams.setPartyVInfo(null);
        xmlParams.setSuppPubInfo(null);
        xmlParams.setSuppPrivInfo(null);
        
        ConcatKDF parameter = ConcatKDF.fromXMLObject(xmlKDM);
        Assert.assertNotNull(parameter);
        Assert.assertTrue(parameter.isInitialized());

        Assert.assertEquals(parameter.getAlgorithm(), EncryptionConstants.ALGO_ID_KEYDERIVATION_CONCATKDF);
        Assert.assertEquals(parameter.getDigestMethod(), SignatureConstants.ALGO_ID_DIGEST_SHA256);

        Assert.assertEquals(parameter.getAlgorithmID(), null);
        Assert.assertEquals(parameter.getPartyUInfo(), null);
        Assert.assertEquals(parameter.getPartyVInfo(), null);
        Assert.assertEquals(parameter.getSuppPubInfo(), null);
        Assert.assertEquals(parameter.getSuppPrivInfo(), null);
    }
    
    @Test
    public void fromXMLObject_EmptyBitstrings_OSJ_355() throws Exception {
        KeyDerivationMethod xmlKDM = buildXMLObject(KeyDerivationMethod.DEFAULT_ELEMENT_NAME);
        xmlKDM.setAlgorithm(EncryptionConstants.ALGO_ID_KEYDERIVATION_CONCATKDF);
        
        ConcatKDFParams xmlParams= buildXMLObject(ConcatKDFParams.DEFAULT_ELEMENT_NAME);
        xmlKDM.getUnknownXMLObjects().add(xmlParams);
        
        DigestMethod xmlDigest = buildXMLObject(DigestMethod.DEFAULT_ELEMENT_NAME);
        xmlDigest.setAlgorithm(SignatureConstants.ALGO_ID_DIGEST_SHA256);
        xmlParams.setDigestMethod(xmlDigest);
        
        xmlParams.setAlgorithmID("00");
        xmlParams.setPartyUInfo("00");
        xmlParams.setPartyVInfo("00");
        xmlParams.setSuppPubInfo("00");
        xmlParams.setSuppPrivInfo("00");
        
        ConcatKDF parameter = ConcatKDF.fromXMLObject(xmlKDM);
        Assert.assertNotNull(parameter);
        Assert.assertTrue(parameter.isInitialized());

        Assert.assertEquals(parameter.getAlgorithm(), EncryptionConstants.ALGO_ID_KEYDERIVATION_CONCATKDF);
        Assert.assertEquals(parameter.getDigestMethod(), SignatureConstants.ALGO_ID_DIGEST_SHA256);

        Assert.assertEquals(parameter.getAlgorithmID(), null);
        Assert.assertEquals(parameter.getPartyUInfo(), null);
        Assert.assertEquals(parameter.getPartyVInfo(), null);
        Assert.assertEquals(parameter.getSuppPubInfo(), null);
        Assert.assertEquals(parameter.getSuppPrivInfo(), null);
    }
    
    @Test
    public void fromXMLObject_InvalidValues() throws Exception {
        KeyDerivationMethod xmlKDM = buildXMLObject(KeyDerivationMethod.DEFAULT_ELEMENT_NAME);
        xmlKDM.setAlgorithm(EncryptionConstants.ALGO_ID_KEYDERIVATION_CONCATKDF);
        
        ConcatKDFParams xmlParams= buildXMLObject(ConcatKDFParams.DEFAULT_ELEMENT_NAME);
        xmlKDM.getUnknownXMLObjects().add(xmlParams);
        
        DigestMethod xmlDigest = buildXMLObject(DigestMethod.DEFAULT_ELEMENT_NAME);
        xmlDigest.setAlgorithm(SignatureConstants.ALGO_ID_DIGEST_SHA256);
        xmlParams.setDigestMethod(xmlDigest);
        
        xmlParams.setAlgorithmID("00AA");
        xmlParams.setPartyUInfo("00BB");
        xmlParams.setPartyVInfo("00CC");
        xmlParams.setSuppPubInfo("00DD");
        xmlParams.setSuppPrivInfo("00EE");
        
        ConcatKDF parameter = ConcatKDF.fromXMLObject(xmlKDM);
        Assert.assertNotNull(parameter);
        Assert.assertTrue(parameter.isInitialized());

        // Testing various invalid values

        KeyDerivationMethod xmlKDMBad = null;
        ConcatKDFParams xmlParamsBad = null;
        
        xmlKDMBad = XMLObjectSupport.cloneXMLObject(xmlKDM);
        xmlKDMBad.setAlgorithm(EncryptionConstants.ALGO_ID_KEYDERIVATION_PBKDF2);
        try {
            ConcatKDF.fromXMLObject(xmlKDMBad);
            Assert.fail("Should have failed invalid XMLObject");
        } catch (ComponentInitializationException e) {
            //expected
        }
        
        xmlKDMBad = XMLObjectSupport.cloneXMLObject(xmlKDM);
        xmlKDMBad.getUnknownXMLObjects().add(buildXMLObject(simpleXMLObjectQName));
        try {
            ConcatKDF.fromXMLObject(xmlKDMBad);
            Assert.fail("Should have failed invalid XMLObject");
        } catch (ComponentInitializationException e) {
            //expected
        }
        
        xmlKDMBad = XMLObjectSupport.cloneXMLObject(xmlKDM);
        xmlParamsBad = (ConcatKDFParams) xmlKDMBad.getUnknownXMLObjects().get(0);
        xmlParamsBad.setDigestMethod(null);
        try {
            ConcatKDF.fromXMLObject(xmlKDMBad);
            Assert.fail("Should have failed invalid XMLObject");
        } catch (ComponentInitializationException e) {
            //expected
        }
        
        xmlKDMBad = XMLObjectSupport.cloneXMLObject(xmlKDM);
        xmlParamsBad = (ConcatKDFParams) xmlKDMBad.getUnknownXMLObjects().get(0);
        xmlParamsBad.setAlgorithmID("01AA");
        try {
            ConcatKDF.fromXMLObject(xmlKDMBad);
            Assert.fail("Should have failed invalid XMLObject");
        } catch (ComponentInitializationException e) {
            //expected
        }
        
        xmlKDMBad = XMLObjectSupport.cloneXMLObject(xmlKDM);
        xmlParamsBad = (ConcatKDFParams) xmlKDMBad.getUnknownXMLObjects().get(0);
        xmlParamsBad.setPartyUInfo("01BB");
        try {
            ConcatKDF.fromXMLObject(xmlKDMBad);
            Assert.fail("Should have failed invalid XMLObject");
        } catch (ComponentInitializationException e) {
            //expected
        }
        
        xmlKDMBad = XMLObjectSupport.cloneXMLObject(xmlKDM);
        xmlParamsBad = (ConcatKDFParams) xmlKDMBad.getUnknownXMLObjects().get(0);
        xmlParamsBad.setPartyVInfo("01CC");
        try {
            ConcatKDF.fromXMLObject(xmlKDMBad);
            Assert.fail("Should have failed invalid XMLObject");
        } catch (ComponentInitializationException e) {
            //expected
        }
        
        xmlKDMBad = XMLObjectSupport.cloneXMLObject(xmlKDM);
        xmlParamsBad = (ConcatKDFParams) xmlKDMBad.getUnknownXMLObjects().get(0);
        xmlParamsBad.setSuppPubInfo("01DD");
        try {
            ConcatKDF.fromXMLObject(xmlKDMBad);
            Assert.fail("Should have failed invalid XMLObject");
        } catch (ComponentInitializationException e) {
            //expected
        }
        
        xmlKDMBad = XMLObjectSupport.cloneXMLObject(xmlKDM);
        xmlParamsBad = (ConcatKDFParams) xmlKDMBad.getUnknownXMLObjects().get(0);
        xmlParamsBad.setSuppPrivInfo("01EE");
        try {
            ConcatKDF.fromXMLObject(xmlKDMBad);
            Assert.fail("Should have failed invalid XMLObject");
        } catch (ComponentInitializationException e) {
            //expected
        }
    }

    @Test
    public void cloning() throws Exception {
        ConcatKDF kdf = new ConcatKDF();
        kdf.setAlgorithmID("AA");
        kdf.setPartyUInfo("BB");
        kdf.setPartyVInfo("CC");
        kdf.setSuppPubInfo("DD");
        kdf.setSuppPrivInfo("EE");
        kdf.setDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA512);
        kdf.initialize();
        
        Assert.assertEquals(kdf.getAlgorithm(), EncryptionConstants.ALGO_ID_KEYDERIVATION_CONCATKDF);
        
        ConcatKDF cloned = kdf.clone();
        
        Assert.assertEquals(cloned.getAlgorithmID(), "AA");
        Assert.assertEquals(cloned.getPartyUInfo(), "BB");
        Assert.assertEquals(cloned.getPartyVInfo(), "CC");
        Assert.assertEquals(cloned.getSuppPubInfo(), "DD");
        Assert.assertEquals(cloned.getSuppPrivInfo(), "EE");
        Assert.assertEquals(cloned.getDigestMethod(), SignatureConstants.ALGO_ID_DIGEST_SHA512);
    }

    @Test
    public void deriveWithDefaults() throws Exception {
        ConcatKDF kdf = new ConcatKDF();
        kdf.initialize();
        
        byte[] secret = HexFormat.of().parseHex("DEADBEEF");
        
        SecretKey derivedKey = kdf.derive(secret, EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128_GCM, null);
        
        Assert.assertNotNull(derivedKey);
        Assert.assertEquals(derivedKey.getAlgorithm(), "AES");
        Assert.assertEquals(derivedKey.getEncoded().length * 8, 128);
    }

    @Test
    public void deriveWithExplicitProperties() throws Exception {
        ConcatKDF kdf = new ConcatKDF();
        kdf.setAlgorithmID("AA");
        kdf.setPartyUInfo("BB");
        kdf.setPartyVInfo("CC");
        kdf.setSuppPubInfo("DD");
        kdf.setSuppPrivInfo("EE");
        kdf.initialize();
        
        byte[] secret = HexFormat.of().parseHex("DEADBEEF");
        
        SecretKey derivedKey = kdf.derive(secret, EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128_GCM, null);
        
        Assert.assertNotNull(derivedKey);
        Assert.assertEquals(derivedKey.getAlgorithm(), "AES");
        Assert.assertEquals(derivedKey.getEncoded().length * 8, 128);
    }

    @Test(expectedExceptions = KeyDerivationException.class)
    public void unknownKeyAlgorithm() throws Exception {
        ConcatKDF kdf = new ConcatKDF();
        kdf.initialize();
        
        byte[] secret = HexFormat.of().parseHex("DEADBEEF");
        
        kdf.derive(secret, "urn:test:InvalidKeyAlgorithm", null);
    }

    @Test(expectedExceptions = KeyDerivationException.class)
    public void nonKeyLengthAlgorithm() throws Exception {
        ConcatKDF kdf = new ConcatKDF();
        kdf.initialize();
        
        byte[] secret = HexFormat.of().parseHex("DEADBEEF");
        
        // Just use this as a stand-in for something which is KeySpecifiedAlgorithm but not KeyLengthSpecifiedAlgorithm
        kdf.derive(secret, SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256, null);
    }

    @Test
    public void nonKeyLengthAlgorithmWithSpecifiedLength() throws Exception {
        ConcatKDF kdf = new ConcatKDF();
        kdf.initialize();
        
        byte[] secret = HexFormat.of().parseHex("DEADBEEF");
        
        // Just use this as a stand-in for something which is KeySpecifiedAlgorithm but not KeyLengthSpecifiedAlgorithm
        SecretKey derivedKey = kdf.derive(secret, SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256, 256);
        
        // This is bogus obviously, but just need to test that a known algo URI that is non-key length works with specified key length
        Assert.assertNotNull(derivedKey);
        Assert.assertEquals(derivedKey.getAlgorithm(), "RSA");
        Assert.assertEquals(derivedKey.getEncoded().length * 8, 256);
    }

    @Test
    public void decodeParam() throws Exception {
        ConcatKDF kdf = new ConcatKDF();
        kdf.initialize();
        
        Assert.assertEquals(kdf.decodeParam(null, "test"), new byte[] {});
        Assert.assertEquals(kdf.decodeParam("    ", "test"), new byte[] {});
        Assert.assertEquals(kdf.decodeParam("00", "test"), new byte[] {0x00});
        Assert.assertEquals(kdf.decodeParam("000000", "test"), new byte[] {0x00, 0x00, 0x00});
        Assert.assertEquals(kdf.decodeParam("AB", "test"), new byte[] {(byte) 0xAB});
        Assert.assertEquals(kdf.decodeParam("ABCD", "test"), new byte[] {(byte) 0xAB, (byte) 0xCD});
        Assert.assertEquals(kdf.decodeParam("DEADBEEF", "test"), new byte[] {(byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF});
        
        try {
            // invalid hex value
            kdf.decodeParam("INVALID", "test");
            Assert.fail("Invalid value should have failed");
        } catch (KeyDerivationException e) {
            //expected
        }
        
        try {
            // invalid hex value
            kdf.decodeParam("A", "test");
            Assert.fail("Invalid value should have failed");
        } catch (KeyDerivationException e) {
            //expected
        }
        
        try {
            // invalid hex value
            kdf.decodeParam("ABC", "test");
            Assert.fail("Invalid value should have failed");
        } catch (KeyDerivationException e) {
            //expected
        }
    }
    
    @Test
    public void padParam() throws Exception {
        Assert.assertEquals(ConcatKDF.padParam(null), null);
        Assert.assertEquals(ConcatKDF.padParam("   "), null);
        
        Assert.assertEquals(ConcatKDF.padParam("AA"), "00AA");
        Assert.assertEquals(ConcatKDF.padParam("   AABBCC   "), "00AABBCC");
    }
    
    @Test
    public void unpadParam() throws Exception {
        Assert.assertEquals(ConcatKDF.unpadParam(null, "test"), null);
        Assert.assertEquals(ConcatKDF.unpadParam("   ", "test"), null);
        
        Assert.assertEquals(ConcatKDF.unpadParam("00AA", "test"), "AA");
        Assert.assertEquals(ConcatKDF.unpadParam("   00AABBCC   ", "test"), "AABBCC");

        // Considered valid per OSJ-355
        Assert.assertEquals(ConcatKDF.unpadParam("00", "test"), "");
        
        try {
            // Unsupported padding
            ConcatKDF.unpadParam("01AA", "test");
            Assert.fail("Invalid value should have failed");
        } catch (KeyDerivationException eA ) {
           //expected 
        }
        
        try {
            // Too short
            ConcatKDF.unpadParam("0", "test");
            Assert.fail("Invalid value should have failed");
        } catch (KeyDerivationException eA ) {
           //expected 
        }
        try {
            // Odd number of hex digits
            ConcatKDF.unpadParam("00A", "test");
            Assert.fail("Invalid value should have failed");
        } catch (KeyDerivationException eA ) {
           //expected 
        }
    }
    
    
    //
    // Derivation tests using test vectors from external sources, and supporting code
    //

    @DataProvider(name = "testVectors")
    public Object[][] testVectors() throws EncodingException {
        return new Object[][] {
            
            // Non-normative vectors.
            // https://github.com/patrickfav/singlestep-kdf/wiki/NIST-SP-800-56C-Rev1:-Non-Official-Test-Vectors
            // Nominally this is for a newer rev of the NIST spec, but the algorithm is the same.
            // Just included a representative subset of these as of 2020-12-30.
            
            // SHA-1 digest
            new Object[] {
                    HexFormat.of().parseHex("d09a6b1a472f930db4f5e6b967900744"),
                    HexFormat.of().parseHex("b117255ab5f1b6b96fc434b0"),
                    128,
                    SignatureConstants.ALGO_ID_DIGEST_SHA1,
                    HexFormat.of().parseHex("b5a3c52e97ae6e8c5069954354eab3c7")},
            
            new Object[] {
                    HexFormat.of().parseHex("343666c0dd34b756e70f759f14c304f5"),
                    HexFormat.of().parseHex("722b28448d7eab85491bce09"),
                    128,
                    SignatureConstants.ALGO_ID_DIGEST_SHA1,
                    HexFormat.of().parseHex("1003b650ddd3f0891a15166db5ec881d")},
            
            new Object[] {
                    HexFormat.of().parseHex("b84acf03ab08652dd7f82fa956933261"),
                    HexFormat.of().parseHex("3d8773ec068c86053a918565"),
                    128,
                    SignatureConstants.ALGO_ID_DIGEST_SHA1,
                    HexFormat.of().parseHex("1635dcd1ce698f736831b4badb68ab2b")},
            
            new Object[] {
                    HexFormat.of().parseHex("8cc24ca3f1d1a8b34783780b79890430"),
                    HexFormat.of().parseHex("f08d4f2d9a8e6d7105c0bc16"),
                    128,
                    SignatureConstants.ALGO_ID_DIGEST_SHA1,
                    HexFormat.of().parseHex("b8e716fb84a420aed4812cd76d9700ee")},
            
            new Object[] {
                    HexFormat.of().parseHex("ebe28edbae5a410b87a479243db3f690"),
                    HexFormat.of().parseHex("e60dd8b28228ce5b9be74d3b"),
                    128,
                    SignatureConstants.ALGO_ID_DIGEST_SHA1,
                    HexFormat.of().parseHex("b4a23963e07f485382cb358a493daec1")},
            
            new Object[] {
                    HexFormat.of().parseHex("ebe28edbae5a410b87a479243db3f690"),
                    HexFormat.of().parseHex("e60dd8b28228ce5b9be74d3b"),
                    192,
                    SignatureConstants.ALGO_ID_DIGEST_SHA1,
                    HexFormat.of().parseHex("b4a23963e07f485382cb358a493daec1759ac7043dbeac37")},
            
            new Object[] {
                    HexFormat.of().parseHex("ebe28edbae5a410b87a479243db3f690"),
                    HexFormat.of().parseHex("e60dd8b28228ce5b9be74d3b"),
                    256,
                    SignatureConstants.ALGO_ID_DIGEST_SHA1,
                    HexFormat.of().parseHex("b4a23963e07f485382cb358a493daec1759ac7043dbeac37152c6ddf105031f0")},

            // SHA-256 digest
            new Object[] {
                    HexFormat.of().parseHex("afc4e154498d4770aa8365f6903dc83b"),
                    HexFormat.of().parseHex("662af20379b29d5ef813e655"),
                    128,
                    SignatureConstants.ALGO_ID_DIGEST_SHA256,
                    HexFormat.of().parseHex("f0b80d6ae4c1e19e2105a37024e35dc6")},
            
            new Object[] {
                    HexFormat.of().parseHex("a3ce8d61d699ad150e196a7ab6736a63"),
                    HexFormat.of().parseHex("ce5cd95a44ee83a8fb83f34c"),
                    128,
                    SignatureConstants.ALGO_ID_DIGEST_SHA256,
                    HexFormat.of().parseHex("5db3455a22b65edfcfde3da3e8d724cd")},
            
            new Object[] {
                    HexFormat.of().parseHex("a9723e56045f0847fdd9c1c78781c8b7"),
                    HexFormat.of().parseHex("e69b6005b78f7d42d0a8ed2a"),
                    128,
                    SignatureConstants.ALGO_ID_DIGEST_SHA256,
                    HexFormat.of().parseHex("ac3878b8cf357976f7fd8266923e1882")},
            
            new Object[] {
                    HexFormat.of().parseHex("a07a5e8df7ee1b2ce2a3d1348edfa8ab"),
                    HexFormat.of().parseHex("e22a8ee34296dd39b56b31fb"),
                    128,
                    SignatureConstants.ALGO_ID_DIGEST_SHA256,
                    HexFormat.of().parseHex("70927d218b6d119268381e9930a4f256")},
            
            new Object[] {
                    HexFormat.of().parseHex("3f892bd8b84dae64a782a35f6eaa8f00"),
                    HexFormat.of().parseHex("ec3f1cd873d28858a58cc39e"),
                    128,
                    SignatureConstants.ALGO_ID_DIGEST_SHA256,
                    HexFormat.of().parseHex("a7c0665298252531e0db37737a374651")},
            
            new Object[] {
                    HexFormat.of().parseHex("3f892bd8b84dae64a782a35f6eaa8f00"),
                    HexFormat.of().parseHex("ec3f1cd873d28858a58cc39e"),
                    192,
                    SignatureConstants.ALGO_ID_DIGEST_SHA256,
                    HexFormat.of().parseHex("a7c0665298252531e0db37737a374651b368275f2048284d")},
            
            new Object[] {
                    HexFormat.of().parseHex("3f892bd8b84dae64a782a35f6eaa8f00"),
                    HexFormat.of().parseHex("ec3f1cd873d28858a58cc39e"),
                    256,
                    SignatureConstants.ALGO_ID_DIGEST_SHA256,
                    HexFormat.of().parseHex("a7c0665298252531e0db37737a374651b368275f2048284d16a166c6d8a90a91")},
            
            // SHA-256 digest
            new Object[] {
                    HexFormat.of().parseHex("108cf63318555c787fa578731dd4f037"),
                    HexFormat.of().parseHex("53191b1dd3f94d83084d61d6"),
                    128,
                    SignatureConstants.ALGO_ID_DIGEST_SHA512,
                    HexFormat.of().parseHex("0ad475c1826da3007637970c8b92b993")},
            
            new Object[] {
                    HexFormat.of().parseHex("35fa6d42e65014f04bdd80ff1404ab27"),
                    HexFormat.of().parseHex("506d9cfe967748d1e6f84bd9"),
                    128,
                    SignatureConstants.ALGO_ID_DIGEST_SHA512,
                    HexFormat.of().parseHex("16739821c3b13dee57e24c092211ddd6")},
            
            new Object[] {
                    HexFormat.of().parseHex("775e83546ce8b41a83656bd723d63c9e"),
                    HexFormat.of().parseHex("514f4d06bf8c1646aeae28fa"),
                    128,
                    SignatureConstants.ALGO_ID_DIGEST_SHA512,
                    HexFormat.of().parseHex("0bce0e54a721367088495c0c4c0683f5")},
            
            new Object[] {
                    HexFormat.of().parseHex("03f1dea7561b885a5601c6e75e405140"),
                    HexFormat.of().parseHex("1e366c4b697d20aa9a54d6f5"),
                    128,
                    SignatureConstants.ALGO_ID_DIGEST_SHA512,
                    HexFormat.of().parseHex("56a2ac8f0eb55fdc4d8a891664edfbdb")},
            
            new Object[] {
                    HexFormat.of().parseHex("e65b1905878b95f68b5535bd3b2b1013"),
                    HexFormat.of().parseHex("830221b1730d9176f807d407"),
                    128,
                    SignatureConstants.ALGO_ID_DIGEST_SHA512,
                    HexFormat.of().parseHex("b8c44bdf0b85a64b6a51c12a06710e37")},
            
            new Object[] {
                    HexFormat.of().parseHex("e65b1905878b95f68b5535bd3b2b1013"),
                    HexFormat.of().parseHex("830221b1730d9176f807d407"),
                    192,
                    SignatureConstants.ALGO_ID_DIGEST_SHA512,
                    HexFormat.of().parseHex("b8c44bdf0b85a64b6a51c12a06710e373d829bb1fda5b4e1")},
            
            new Object[] {
                    HexFormat.of().parseHex("e65b1905878b95f68b5535bd3b2b1013"),
                    HexFormat.of().parseHex("830221b1730d9176f807d407"),
                    256,
                    SignatureConstants.ALGO_ID_DIGEST_SHA512,
                    HexFormat.of().parseHex("b8c44bdf0b85a64b6a51c12a06710e373d829bb1fda5b4e1a20795c6199594f6")},
            
            
        };
    }
    
    @Test(dataProvider = "testVectors")
    public void deriveTestVectors(byte[] secret, byte[] otherInfo, Integer keyLength, String digestMethod,
            byte[] keyBytes) throws Exception {
        
        ConcatKDF kdf = new ConcatKDF();
        kdf.setDigestMethod(digestMethod);
        kdf.initialize();
        
        byte[] deriveKeyBytes = kdf.derive(secret, otherInfo, keyLength);
        
        Assert.assertNotNull(deriveKeyBytes);
        Assert.assertEquals(deriveKeyBytes.length * 8, keyLength.intValue());
        Assert.assertEquals(deriveKeyBytes, keyBytes);
    }
    
}
