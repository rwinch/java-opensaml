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

package org.opensaml.xmlsec.signature.support.tests;

import java.io.IOException;
import java.security.KeyPair;
import java.util.List;

import javax.annotation.Nonnull;

import org.apache.xml.security.utils.resolver.ResourceResolver;
import org.apache.xml.security.utils.resolver.implementations.ResolverDirectHTTP;
import org.opensaml.core.testing.XMLObjectBaseTestCase;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilder;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.crypto.KeySupport;
import org.opensaml.xmlsec.mock.SignableSimpleXMLObject;
import org.opensaml.xmlsec.mock.SignableSimpleXMLObjectBuilder;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.DocumentInternalIDContentReference;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.opensaml.xmlsec.signature.support.Signer;
import org.opensaml.xmlsec.signature.support.URIContentReference;
import org.slf4j.Logger;
import org.springframework.core.io.ClassPathResource;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.w3c.dom.Element;

import net.shibboleth.shared.primitive.LoggerFactory;
import net.shibboleth.shared.spring.resource.ResourceHelper;
import net.shibboleth.shared.testing.EmbeddedJetty;
import net.shibboleth.shared.xml.SerializeSupport;
import net.shibboleth.shared.xml.impl.BasicParserPool;

@SuppressWarnings({"javadoc", "null"})
public class DetachedSignatureTest extends XMLObjectBaseTestCase {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(EnvelopedSignatureTest.class);

    /** Key resolver containing proper verification key. */
    private BasicCredential goodCredential;

    /** Key resolver containing invalid verification key. */
    private BasicCredential badCredential;

    /** Builder of mock XML objects. */
    private SignableSimpleXMLObjectBuilder sxoBuilder;

    /** Builder of Signature XML objects. */
    private XMLObjectBuilder<Signature> sigBuilder;

    /** Parser pool used to parse example config files. */
    private BasicParserPool parserPool;

    /** Signature algorithm URI. */
    private String algoURI = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1;

    @BeforeMethod
    protected void setUp() throws Exception {
        KeyPair keyPair = KeySupport.generateKeyPair("RSA", 1024, null);
        goodCredential = CredentialSupport.getSimpleCredential(keyPair.getPublic(), keyPair.getPrivate());

        keyPair = KeySupport.generateKeyPair("RSA", 1024, null);
        badCredential = CredentialSupport.getSimpleCredential(keyPair.getPublic(), null);

        sxoBuilder = new SignableSimpleXMLObjectBuilder();
        sigBuilder = XMLObjectProviderRegistrySupport.getBuilderFactory().<Signature>ensureBuilder(
                Signature.DEFAULT_ELEMENT_NAME);

        parserPool = new BasicParserPool();
        parserPool.setNamespaceAware(true);
    }

    /**
     * Tests creating a detached signature within the same document as the element signed and then verifying it.
     * 
     * @throws MarshallingException thrown if the XMLObject tree can not be marshalled
     * @throws UnmarshallingException thrown if the signature can not be unmarshalled
     * @throws SignatureException ...
     */
    @Test
    public void testInternalSignatureAndVerification() throws MarshallingException, UnmarshallingException,
            SignatureException {
        SignableSimpleXMLObject sxo = getXMLObjectWithSignature();
        Signature signature = sxo.getSignature();

        final Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory().ensureMarshaller(sxo);
        Element signedElement = marshaller.marshall(sxo);

        assert signature != null;
        Signer.signObject(signature);
        if (log.isDebugEnabled()) {
            log.debug("Marshalled deatched Signature: \n" + SerializeSupport.nodeToString(signedElement));
        }

        final Unmarshaller unmarshaller = XMLObjectProviderRegistrySupport.getUnmarshallerFactory().ensureUnmarshaller(signedElement);
        sxo = (SignableSimpleXMLObject) unmarshaller.unmarshall(signedElement);
        final List<XMLObject> children = sxo.getOrderedChildren();
        assert children != null;
        signature = (Signature) children.get(1);

        SignatureValidator.validate(signature, goodCredential);

        try {
            SignatureValidator.validate(signature, badCredential);
            Assert.fail("Validated signature with improper public key");
        } catch (SignatureException e) {
            // expected
        }
    }

    /**
     * Tests creating a detached signature within a different document as the element signed and then verifying it. The
     * external references used are the InCommon and InQueue metadata files.
     * 
     * @throws MarshallingException thrown if the XMLObject tree can not be marshalled
     * @throws SignatureException
     * @throws IOException 
     */
    @Test
    public void testExternalSignatureAndVerification() throws MarshallingException, SignatureException, IOException {
        // This is necessary as of Santuario 2.3.0, which removed the -DirectHTTP and -LocalFilesystem resolvers by default.
        // Unfortunately it's stored in static storage and no way to clear or reset after the test.
        ResourceResolver.register(new ResolverDirectHTTP(), false);
        
        Signature signature = sigBuilder.buildObject(Signature.DEFAULT_ELEMENT_NAME);
        signature.setSigningCredential(goodCredential);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA);

        //Note: we have to use a http URL here, not https, as current default Santuario HTTP ResourceResolver doesn't support https URLs.
        URIContentReference contentReference = new URIContentReference("http://localhost:8080/InCommon-metadata.xml");
        contentReference.getTransforms().add(SignatureConstants.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
        contentReference.setDigestAlgorithm(SignatureConstants.ALGO_ID_DIGEST_SHA1);
        signature.getContentReferences().add(contentReference);

        Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory().ensureMarshaller(signature);
        Element signatureElement = marshaller.marshall(signature);
        
        try (final EmbeddedJetty jetty = new EmbeddedJetty()) {
            jetty.startServer(new EmbeddedJetty.ResourceHandler(200,
                    ResourceHelper.of(new ClassPathResource("org/opensaml/xmlsec/signature/support/InCommon-metadata.xml"))));

            Signer.signObject(signature);
            if (log.isDebugEnabled()) {
                log.debug("Marshalled deatched Signature: \n" + SerializeSupport.nodeToString(signatureElement));
            }

            SignatureValidator.validate(signature, goodCredential);
            
            try {
                SignatureValidator.validate(signature, badCredential);
                Assert.fail("Validated signature with improper public key");
            } catch (SignatureException e) {
                // expected
            }
        }
    }

    /**
     * Unmarshalls the XML DSIG spec RSA example signature and verifies it with the key contained in the KeyInfo.
     * 
     * @throws IOException thrown if the signature can not be fetched from the W3C site
     * @throws MalformedURLException thrown if the signature can not be fetched from the W3C site
     * @throws XMLParserException thrown if the signature is not valid XML
     * @throws UnmarshallingException thrown if the signature DOM can not be unmarshalled
     * @throws ValidationException thrown if the Signature does not validate against the key
     * @throws GeneralSecurityException
     * @throws SecurityException
     */
// TODO this test now fails because the detached signature document is a signature over a document that has now changed
//    public void testUnmarshallExternalSignatureAndVerification() throws IOException, MalformedURLException,
//            XMLParserException, UnmarshallingException, ValidationException, GeneralSecurityException, SecurityException {
//        String signatureLocation = "http://www.w3.org/TR/xmldsig-core/signature-example-rsa.xml";
//        InputStream ins = new URL(signatureLocation).openStream();
//        Element signatureElement = parserPool.parse(ins).getDocumentElement();
//
//        Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory().getUnmarshaller(signatureElement);
//        Signature signature = (Signature) unmarshaller.unmarshall(signatureElement);
//
//        KeyInfoCredentialResolver resolver = XMLSecurityTestingHelper.buildBasicInlineKeyInfoResolver();
//
//        KeyInfoCriterion criteria = new KeyInfoCriterion(signature.getKeyInfo());
//        CriteriaSet criteriaSet = new CriteriaSet(criteria);
//        Credential credential = resolver.resolveSingle(criteriaSet);
//        SignatureValidator sigValidator = new SignatureValidator(credential);
//        sigValidator.validate(signature);
//    }

    /**
     * Creates a XMLObject that has another XMLObject and a Signature as children. The Signature is is a detached
     * signature of its sibling.
     * 
     * @return the XMLObject
     */
    private SignableSimpleXMLObject getXMLObjectWithSignature() {
        SignableSimpleXMLObject rootSXO = sxoBuilder.buildObject();

        SignableSimpleXMLObject childSXO = sxoBuilder.buildObject();
        childSXO.setId("FOO");
        rootSXO.getSimpleXMLObjects().add(childSXO);

        Signature sig = sigBuilder.buildObject(Signature.DEFAULT_ELEMENT_NAME);
        sig.setSigningCredential(goodCredential);
        sig.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        sig.setSignatureAlgorithm(algoURI);

        DocumentInternalIDContentReference contentReference = new DocumentInternalIDContentReference("FOO");
        contentReference.getTransforms().add(SignatureConstants.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
        contentReference.setDigestAlgorithm(SignatureConstants.ALGO_ID_DIGEST_SHA1);
        sig.getContentReferences().add(contentReference);

        rootSXO.setSignature(sig);
        return rootSXO;
    }
}
