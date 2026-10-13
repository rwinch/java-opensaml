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

import org.opensaml.core.testing.OpenSAMLInitBaseTestCase;
import org.opensaml.security.crypto.JCAConstants;
import org.opensaml.xmlsec.derivation.KeyDerivationException;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.testng.Assert;
import org.testng.annotations.Test;

import net.shibboleth.shared.codec.Base64Support;

@SuppressWarnings({"javadoc", "null"})
public class DHLegacyKDFTest extends OpenSAMLInitBaseTestCase {
    
    @Test
    public void specTestVector() throws Exception {
        // This tests the example test data from XML Encryption 1.1 section 5.6.2.2.
        DHLegacyKDF kdf = new DHLegacyKDF();
        kdf.setDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA1);
        kdf.setNonce("Zm9v");
        
        final String nonce = kdf.getNonce();
        assert nonce != null;
        byte[] digestCounter1 = kdf.digest(
                1,
                JCAConstants.DIGEST_SHA1,
                HexFormat.of().parseHex("DEADBEEF"),
                "Example:Block/Alg",
                80,
                Base64Support.decode(nonce));
        
        // The value in the original spec document Example 41 is incorrect, as indicated by the errata:
        // https://www.w3.org/2008/xmlsec/errata/xmlenc-core-11-errata.html
        // This is the correct value from the errata. (Yes, this wasted a lot of time...).
        Assert.assertEquals(digestCounter1, HexFormat.of().parseHex("59D9BA5E06072C1194091952B01B8360534AB11E"));
       
        byte[] derived = kdf.deriveBytes(
                HexFormat.of().parseHex("DEADBEEF"),
                "Example:Block/Alg",
                80);
        Assert.assertEquals(derived.length * 8, 80);
        
        // Note we can't really test an actual SecretKey derivation b/c 
        // "Example:Block/Alg" above is not a real algorithm and so can't resolve the JCA ID.
    }
    
    @Test
    public void basic() throws Exception {
        DHLegacyKDF kdf = new DHLegacyKDF(); 
        kdf.setDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA256);
        kdf.setNonce("Zm9v");
        
        SecretKey secretKey = null;
        
        secretKey = kdf.derive(HexFormat.of().parseHex("DEADBEEF"), EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128, null);
        Assert.assertNotNull(secretKey);
        Assert.assertEquals(secretKey.getEncoded().length * 8, 128);
        
        secretKey = kdf.derive(HexFormat.of().parseHex("DEADBEEF"), EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128, 128);
        Assert.assertNotNull(secretKey);
        Assert.assertEquals(secretKey.getEncoded().length * 8, 128);
        
        secretKey = kdf.derive(HexFormat.of().parseHex("DEADBEEF"), EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES192, null);
        Assert.assertNotNull(secretKey);
        Assert.assertEquals(secretKey.getEncoded().length * 8, 192);
        
        secretKey = kdf.derive(HexFormat.of().parseHex("DEADBEEF"), EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES192, 192);
        Assert.assertNotNull(secretKey);
        Assert.assertEquals(secretKey.getEncoded().length * 8, 192);
        
        secretKey = kdf.derive(HexFormat.of().parseHex("DEADBEEF"), EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256, null);
        Assert.assertNotNull(secretKey);
        Assert.assertEquals(secretKey.getEncoded().length * 8, 256);
        
        secretKey = kdf.derive(HexFormat.of().parseHex("DEADBEEF"), EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256, 256);
        Assert.assertNotNull(secretKey);
        Assert.assertEquals(secretKey.getEncoded().length * 8, 256);
    }

    @Test
    public void missingNonce() throws Exception {
        DHLegacyKDF kdf = new DHLegacyKDF(); 
        kdf.setDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA256);
        
        SecretKey secretKey = null;
        
        secretKey = kdf.derive(HexFormat.of().parseHex("DEADBEEF"), EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128, null);
        Assert.assertNotNull(secretKey);
        Assert.assertEquals(secretKey.getEncoded().length * 8, 128);
    }
        
    @Test(expectedExceptions=KeyDerivationException.class)
    public void missingDigest() throws Exception {
        DHLegacyKDF kdf = new DHLegacyKDF(); 
        kdf.setNonce("Zm9v");
        
        kdf.derive(HexFormat.of().parseHex("DEADBEEF"), EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128, null);
    }
        
    @Test(expectedExceptions=KeyDerivationException.class)
    public void unknownKeyAlgorithm() throws Exception {
        DHLegacyKDF kdf = new DHLegacyKDF(); 
        kdf.setDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA256);
        kdf.setNonce("Zm9v");
        
        kdf.derive(HexFormat.of().parseHex("DEADBEEF"), "urn:test:invalid", null);
    }
        
    @Test(expectedExceptions=KeyDerivationException.class)
    public void unknownDigestAlgorithm() throws Exception {
        DHLegacyKDF kdf = new DHLegacyKDF(); 
        kdf.setDigestMethod("urn:test:invalid");
        kdf.setNonce("Zm9v");
        
        kdf.derive(HexFormat.of().parseHex("DEADBEEF"), EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128, 128);
    }
        
    @Test(expectedExceptions=KeyDerivationException.class)
    public void keyLengthMismatch() throws Exception {
        DHLegacyKDF kdf = new DHLegacyKDF(); 
        kdf.setDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA256);
        kdf.setNonce("Zm9v");
        
        kdf.derive(HexFormat.of().parseHex("DEADBEEF"), EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128, 256);
    }
        
    @Test(expectedExceptions=KeyDerivationException.class)
    public void invalidNonce() throws Exception {
        DHLegacyKDF kdf = new DHLegacyKDF(); 
        kdf.setDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA256);
        kdf.setNonce("INVALID!!!!@@$$##");
        
        kdf.derive(HexFormat.of().parseHex("DEADBEEF"), EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128, 128);
    }
        
}
