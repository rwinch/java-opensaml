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

package org.opensaml.saml.metadata.resolver.index.impl;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Set;

import org.opensaml.core.testing.XMLObjectBaseTestCase;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.binding.artifact.SAMLSourceIDArtifact;
import org.opensaml.saml.common.binding.artifact.SAMLSourceLocationArtifact;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.criterion.ArtifactCriterion;
import org.opensaml.saml.ext.saml1md.SourceID;
import org.opensaml.saml.metadata.resolver.index.MetadataIndexKey;
import org.opensaml.saml.metadata.resolver.index.impl.SAMLArtifactMetadataIndex.ArtifactSourceIDMetadataIndexKey;
import org.opensaml.saml.saml1.binding.artifact.SAML1ArtifactType0002;
import org.opensaml.saml.saml2.binding.artifact.SAML2ArtifactType0004;
import org.opensaml.saml.saml2.metadata.ArtifactResolutionService;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.Extensions;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SSODescriptor;
import org.opensaml.security.crypto.JCAConstants;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import net.shibboleth.shared.resolver.CriteriaSet;

@SuppressWarnings("javadoc")
public class SAMLArtifactMetadataIndexTest extends XMLObjectBaseTestCase {
    
    private SAMLArtifactMetadataIndex metadataIndex;
    
    private String entityID = "https://www.example.com/saml";
    private byte[] entityIDSourceID;
    private String sourceLocation1 = "https://www.example.com/saml/artifactResolve1";
    private String sourceLocation2 = "https://www.example.com/saml/artifactResolve2";
            
    private EntityDescriptor descriptor;
    
    private SourceID extSourceID1a, extSourceID1b, extSourceID2;
    
    private MetadataIndexKey entityIDSourceIDKey, extSourceIDKey1a, extSourceIDKey1b, extSourceIDKey2, sourceLocationKey1, sourceLocationKey2;
    
    private SAMLSourceIDArtifact sourceIDArtifact;
    private SAMLSourceLocationArtifact sourceLocationArtifact1;
    
    
    @BeforeMethod
    protected void setUp() throws NoSuchAlgorithmException, UnsupportedEncodingException {
        metadataIndex = new SAMLArtifactMetadataIndex();
        
        MessageDigest sha1Digester = MessageDigest.getInstance(JCAConstants.DIGEST_SHA1);
        entityIDSourceID = sha1Digester.digest(entityID.getBytes("UTF-8"));
        
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        
        byte[] messageHandle = new byte[20];
        secureRandom.nextBytes(messageHandle);
        
        sourceIDArtifact = new SAML2ArtifactType0004(new byte[] {0, 0} , entityIDSourceID, messageHandle);
        
        entityIDSourceIDKey = new SAMLArtifactMetadataIndex.ArtifactSourceIDMetadataIndexKey(entityIDSourceID);
        
        sourceLocationArtifact1 = new SAML1ArtifactType0002(messageHandle, sourceLocation1);
        
        descriptor = (EntityDescriptor) XMLObjectSupport.buildXMLObject(EntityDescriptor.DEFAULT_ELEMENT_NAME);
        descriptor.setEntityID(entityID);
        
        sourceLocationKey1 = new SAMLArtifactMetadataIndex.ArtifactSourceLocationMetadataIndexKey(sourceLocation1);
        sourceLocationKey2 = new SAMLArtifactMetadataIndex.ArtifactSourceLocationMetadataIndexKey(sourceLocation2);
        
        byte[] secondarySourceID;
        
        secondarySourceID = new byte[20];
        secureRandom.nextBytes(secondarySourceID);
        extSourceIDKey1a = new ArtifactSourceIDMetadataIndexKey(secondarySourceID);
        extSourceID1a = buildXMLObject(SourceID.DEFAULT_ELEMENT_NAME);
        extSourceID1a.setValue(HexFormat.of().formatHex(secondarySourceID));
        
        secondarySourceID = new byte[20];
        secureRandom.nextBytes(secondarySourceID);
        extSourceIDKey1b = new ArtifactSourceIDMetadataIndexKey(secondarySourceID);
        extSourceID1b = buildXMLObject(SourceID.DEFAULT_ELEMENT_NAME);
        extSourceID1b.setValue(HexFormat.of().formatHex(secondarySourceID));
        
        secondarySourceID = new byte[20];
        secureRandom.nextBytes(secondarySourceID);
        extSourceIDKey2 = new ArtifactSourceIDMetadataIndexKey(secondarySourceID);
        extSourceID2 = buildXMLObject(SourceID.DEFAULT_ELEMENT_NAME);
        extSourceID2.setValue(HexFormat.of().formatHex(secondarySourceID));
    }
    
    @Test
    public void testGenerateKeysFromDescriptorEntityIDOnly() {
        final Set<MetadataIndexKey> keys = metadataIndex.generateKeys(descriptor);
        assert keys != null;
        
        Assert.assertEquals(keys.size(), 1);
        Assert.assertTrue(keys.contains(entityIDSourceIDKey));
    }
    
    @Test
    public void testGenerateKeysFromDescriptorWithOneARS() {
        SSODescriptor roleDescriptor1 = buildXMLObject(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
        ArtifactResolutionService ars1 = buildXMLObject(ArtifactResolutionService.DEFAULT_ELEMENT_NAME);
        ars1.setLocation(sourceLocation1);
        ars1.setBinding(SAMLConstants.SAML2_SOAP11_BINDING_URI);
        roleDescriptor1.getArtifactResolutionServices().add(ars1);
        descriptor.getRoleDescriptors().add(roleDescriptor1);
        
        final Set<MetadataIndexKey> keys = metadataIndex.generateKeys(descriptor);
        assert keys != null;
        
        Assert.assertEquals(keys.size(), 2);
        Assert.assertTrue(keys.contains(entityIDSourceIDKey));
        Assert.assertTrue(keys.contains(sourceLocationKey1));
    }
    
    @Test
    public void testGenerateKeysFromDescriptorWithMultipleARS() {
        SSODescriptor roleDescriptor1 = buildXMLObject(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
        ArtifactResolutionService ars1 = buildXMLObject(ArtifactResolutionService.DEFAULT_ELEMENT_NAME);
        ars1.setLocation(sourceLocation1);
        ars1.setBinding(SAMLConstants.SAML2_SOAP11_BINDING_URI);
        roleDescriptor1.getArtifactResolutionServices().add(ars1);
        descriptor.getRoleDescriptors().add(roleDescriptor1);
        
        SSODescriptor roleDescriptor2 = buildXMLObject(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
        ArtifactResolutionService ars2 = buildXMLObject(ArtifactResolutionService.DEFAULT_ELEMENT_NAME);
        ars2.setLocation(sourceLocation2);
        ars2.setBinding(SAMLConstants.SAML2_SOAP11_BINDING_URI);
        roleDescriptor2.getArtifactResolutionServices().add(ars2);
        descriptor.getRoleDescriptors().add(roleDescriptor2);
        
        final Set<MetadataIndexKey> keys = metadataIndex.generateKeys(descriptor);
        assert keys != null;
        
        Assert.assertEquals(keys.size(), 3);
        Assert.assertTrue(keys.contains(entityIDSourceIDKey));
        Assert.assertTrue(keys.contains(sourceLocationKey1));
        Assert.assertTrue(keys.contains(sourceLocationKey2));
    }
    
    @Test
    public void testGenerateKeysFromDescriptorWithOneExtension() {
        RoleDescriptor roleDescriptor1 = buildXMLObject(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
        Extensions extensions1 = buildXMLObject(Extensions.DEFAULT_ELEMENT_NAME);
        extensions1.getUnknownXMLObjects().add(extSourceID1a);
        roleDescriptor1.setExtensions(extensions1);
        descriptor.getRoleDescriptors().add(roleDescriptor1);
        
        final Set<MetadataIndexKey> keys = metadataIndex.generateKeys(descriptor);
        assert keys != null;
        
        Assert.assertEquals(keys.size(), 2);
        Assert.assertTrue(keys.contains(entityIDSourceIDKey));
        Assert.assertTrue(keys.contains(extSourceIDKey1a));
    }
    
    @Test
    public void testGenerateKeysFromDescriptorWithMultipleExtensions() {
        RoleDescriptor roleDescriptor1 = buildXMLObject(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
        Extensions extensions1 = buildXMLObject(Extensions.DEFAULT_ELEMENT_NAME);
        extensions1.getUnknownXMLObjects().add(extSourceID1a);
        extensions1.getUnknownXMLObjects().add(extSourceID1b);
        roleDescriptor1.setExtensions(extensions1);
        descriptor.getRoleDescriptors().add(roleDescriptor1);
        
        RoleDescriptor roleDescriptor2 = buildXMLObject(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
        Extensions extensions2 = buildXMLObject(Extensions.DEFAULT_ELEMENT_NAME);
        extensions2.getUnknownXMLObjects().add(extSourceID2);
        roleDescriptor2.setExtensions(extensions2);
        descriptor.getRoleDescriptors().add(roleDescriptor2);
        
        final Set<MetadataIndexKey> keys = metadataIndex.generateKeys(descriptor);
        assert keys != null;
        
        Assert.assertEquals(keys.size(), 4);
        Assert.assertTrue(keys.contains(entityIDSourceIDKey));
        Assert.assertTrue(keys.contains(extSourceIDKey1a));
        Assert.assertTrue(keys.contains(extSourceIDKey1b));
        Assert.assertTrue(keys.contains(extSourceIDKey2));
    }
    
    @Test
    public void testGenerateKeysFromDescriptorWithExtensionAndARS() {
        SSODescriptor roleDescriptor1 = buildXMLObject(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
        Extensions extensions1 = buildXMLObject(Extensions.DEFAULT_ELEMENT_NAME);
        extensions1.getUnknownXMLObjects().add(extSourceID1a);
        roleDescriptor1.setExtensions(extensions1);
        
        ArtifactResolutionService ars1 = buildXMLObject(ArtifactResolutionService.DEFAULT_ELEMENT_NAME);
        ars1.setLocation(sourceLocation1);
        ars1.setBinding(SAMLConstants.SAML2_SOAP11_BINDING_URI);
        roleDescriptor1.getArtifactResolutionServices().add(ars1);
        
        descriptor.getRoleDescriptors().add(roleDescriptor1);
        
        final Set<MetadataIndexKey> keys = metadataIndex.generateKeys(descriptor);
        assert keys != null;
        
        Assert.assertEquals(keys.size(), 3);
        Assert.assertTrue(keys.contains(entityIDSourceIDKey));
        Assert.assertTrue(keys.contains(extSourceIDKey1a));
        Assert.assertTrue(keys.contains(sourceLocationKey1));
    }
    
    @Test
    public void testGenerateSourceIDKeysFromCriteria() {
        CriteriaSet criteriaSet = new CriteriaSet();
        
        criteriaSet.add(new ArtifactCriterion(sourceIDArtifact));
        
        final Set<MetadataIndexKey> keys = metadataIndex.generateKeys(criteriaSet);
        assert keys != null;
        
        Assert.assertEquals(keys.size(), 1);
        Assert.assertTrue(keys.contains(entityIDSourceIDKey));
    }
    
    @Test
    public void testGenerateSourceLocationKeysFromCriteria() {
        CriteriaSet criteriaSet = new CriteriaSet();
        
        criteriaSet.add(new ArtifactCriterion(sourceLocationArtifact1));
        
        final Set<MetadataIndexKey> keys = metadataIndex.generateKeys(criteriaSet);
        assert keys != null;
        
        Assert.assertEquals(keys.size(), 1);
        Assert.assertTrue(keys.contains(sourceLocationKey1));
    }
    
    @Test
    public void testSourceIDKey() throws UnsupportedEncodingException, NoSuchAlgorithmException {
        MessageDigest sha1Digester = MessageDigest.getInstance(JCAConstants.DIGEST_SHA1);
        
        MetadataIndexKey keySame = new SAMLArtifactMetadataIndex.ArtifactSourceIDMetadataIndexKey(
                sha1Digester.digest(entityID.getBytes("UTF-8")));
                
        sha1Digester.reset();
        MetadataIndexKey keyDifferent = new SAMLArtifactMetadataIndex.ArtifactSourceIDMetadataIndexKey(
                sha1Digester.digest("foobar".getBytes("UTF-8")));
        
        Assert.assertEquals(entityIDSourceIDKey, keySame);
        Assert.assertTrue(entityIDSourceIDKey.hashCode() == keySame.hashCode());
        
        Assert.assertNotEquals(entityIDSourceIDKey, keyDifferent);
    }

    @Test
    public void testSourceLocationKey() throws UnsupportedEncodingException, NoSuchAlgorithmException {
        MetadataIndexKey keySame = 
                new SAMLArtifactMetadataIndex.ArtifactSourceLocationMetadataIndexKey(sourceLocation1);
                
        MetadataIndexKey keySameCanonicalized = 
                new SAMLArtifactMetadataIndex.ArtifactSourceLocationMetadataIndexKey("HTTPS://WWW.EXAMPLE.COM:443/saml/artifactResolve1?foo=x&bar=y#someFragment");
                
        MetadataIndexKey keyDifferent = 
                new SAMLArtifactMetadataIndex.ArtifactSourceLocationMetadataIndexKey("https://bogus.example.org/sp");
                
        
        Assert.assertEquals(sourceLocationKey1, keySame);
        Assert.assertTrue(sourceLocationKey1.hashCode() == keySame.hashCode());
        
        Assert.assertEquals(sourceLocationKey1, keySameCanonicalized);
        Assert.assertTrue(sourceLocationKey1.hashCode() == keySameCanonicalized.hashCode());
        
        Assert.assertNotEquals(sourceLocationKey1, keyDifferent);
    }

}
