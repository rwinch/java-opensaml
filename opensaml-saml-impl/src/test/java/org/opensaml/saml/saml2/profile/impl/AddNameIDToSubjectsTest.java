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

package org.opensaml.saml.saml2.profile.impl;

import java.io.File;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Arrays;
import java.util.List;
import java.util.function.Function;

import javax.annotation.Nonnull;

import net.shibboleth.shared.collection.CollectionSupport;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.logic.PredicateSupport;
import net.shibboleth.shared.primitive.AnnotationsSupport;
import net.shibboleth.shared.resolver.ResolverException;

import org.opensaml.core.testing.XMLObjectBaseTestCase;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.profile.testing.ActionTestingSupport;
import org.opensaml.profile.testing.RequestContextBuilder;
import org.opensaml.saml.common.SAMLException;
import org.opensaml.saml.common.SAMLObjectBuilder;
import org.opensaml.saml.common.binding.impl.SAMLMetadataLookupHandlerTest;
import org.opensaml.saml.common.profile.SAMLEventIds;
import org.opensaml.saml.common.profile.logic.AffiliationNameIDPolicyPredicate;
import org.opensaml.saml.metadata.resolver.impl.FilesystemMetadataResolver;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.profile.AbstractSAML2NameIDGenerator;
import org.opensaml.saml.saml2.testing.SAML2ActionTestingSupport;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/** Test for {@link AddNameIDToSubjects}. */
@SuppressWarnings({"null", "javadoc"})
public class AddNameIDToSubjectsTest extends XMLObjectBaseTestCase {

    private static final String NAME_QUALIFIER = "https://idp.example.org";
    
    private FilesystemMetadataResolver metadataResolver;
    
    private SAMLObjectBuilder<NameIDPolicy> policyBuilder;
    
    private ChainingSAML2NameIDGenerator generator;

    private ProfileRequestContext prc;
    
    private AddNameIDToSubjects action;
    
    @BeforeClass
    public void classSetUp() throws ResolverException, URISyntaxException, ComponentInitializationException {
        final URL mdURL = SAMLMetadataLookupHandlerTest.class
                .getResource("/org/opensaml/saml/saml2/profile/impl/affiliation-metadata.xml");
        final File mdFile = new File(mdURL.toURI());

        metadataResolver = new FilesystemMetadataResolver(mdFile);
        metadataResolver.setParserPool(parserPool);
        metadataResolver.setId("md");
        metadataResolver.initialize();
    }
    
    @AfterClass
    public void classTearDown() {
        AnnotationsSupport.callOnTeardownAnnotations(metadataResolver);
    }
    
    @BeforeMethod
    public void setUp() throws ComponentInitializationException {
        prc = new RequestContextBuilder().buildProfileRequestContext();
        
        action = new AddNameIDToSubjects();
        
        final MockSAML2NameIDGenerator mock = new MockSAML2NameIDGenerator("foo");
        mock.setFormat(NameID.X509_SUBJECT);
        mock.initialize();

        final MockSAML2NameIDGenerator mock2 = new MockSAML2NameIDGenerator("bar");
        mock2.setFormat(NameID.EMAIL);
        mock2.setActivationCondition(PredicateSupport.alwaysFalse());
        mock2.initialize();

        final MockSAML2NameIDGenerator mock3 = new MockSAML2NameIDGenerator("baz");
        mock3.setFormat(NameID.EMAIL);
        mock3.initialize();

        final MockSAML2NameIDGenerator mock4 = new MockSAML2NameIDGenerator("baf");
        mock4.setFormat(NameID.PERSISTENT);
        mock4.initialize();
        
        generator = new ChainingSAML2NameIDGenerator();
        generator.setGenerators(CollectionSupport.listOf(mock, mock2, mock3, mock4));

        action.setNameIDGenerator(generator);
        
        policyBuilder = (SAMLObjectBuilder<NameIDPolicy>)
                XMLObjectProviderRegistrySupport.getBuilderFactory().<NameIDPolicy>ensureBuilder(
                        NameIDPolicy.DEFAULT_ELEMENT_NAME);
    }
    
    @Test
    public void testNoMessage() throws ComponentInitializationException {
        action.initialize();
        action.execute(prc);
        ActionTestingSupport.assertProceedEvent(prc);
        
        final Assertion assertion = (Assertion) prc.ensureOutboundMessageContext().ensureMessage();
        final Subject subject = assertion.getSubject();
        Assert.assertNull(subject);
    }

    @Test
    public void testNoAssertions() throws ComponentInitializationException {
        prc.ensureOutboundMessageContext().setMessage(SAML2ActionTestingSupport.buildResponse());
        action.initialize();
        action.execute(prc);
        ActionTestingSupport.assertProceedEvent(prc);
        Assert.assertTrue(((Response) prc.ensureOutboundMessageContext().ensureMessage()).getAssertions().isEmpty());
    }

    @Test void testRequiredFormat() throws ComponentInitializationException {
        addAssertions();
        final AuthnRequest request = SAML2ActionTestingSupport.buildAuthnRequest();
        final NameIDPolicy policy = policyBuilder.buildObject();
        policy.setFormat(NameID.EMAIL);
        request.setNameIDPolicy(policy);
        prc.ensureInboundMessageContext().setMessage(request);
        
        action.initialize();
        action.execute(prc);
        ActionTestingSupport.assertProceedEvent(prc);
        
        Assertion assertion = ((Response) prc.ensureOutboundMessageContext().ensureMessage()).getAssertions().get(0);
        Subject subject = assertion.getSubject();
        assert subject != null;
        NameID nameID = subject.getNameID();
        assert nameID != null;
        Assert.assertEquals(nameID.getValue(), "baz");
        Assert.assertEquals(nameID.getFormat(), NameID.EMAIL);

        assertion = ((Response) prc.ensureOutboundMessageContext().ensureMessage()).getAssertions().get(1);
        subject = assertion.getSubject();
        assert subject != null;
        nameID = subject.getNameID();
        assert nameID != null;
        Assert.assertEquals(nameID.getValue(), "baz");
        Assert.assertEquals(nameID.getFormat(), NameID.EMAIL);
    }

    @Test void testRequiredFormatError() throws ComponentInitializationException {
        addAssertions();
        final AuthnRequest request = SAML2ActionTestingSupport.buildAuthnRequest();
        final NameIDPolicy policy = policyBuilder.buildObject();
        policy.setFormat(NameID.KERBEROS);
        request.setNameIDPolicy(policy);
        prc.ensureInboundMessageContext().setMessage(request);
        
        action.initialize();
        action.execute(prc);
        ActionTestingSupport.assertEvent(prc, SAMLEventIds.INVALID_NAMEID_POLICY);
        
        Assertion assertion = ((Response) prc.ensureOutboundMessageContext().ensureMessage()).getAssertions().get(0);
        Subject subject = assertion.getSubject();
        Assert.assertNull(subject);
    }
    
    @Test void testQualifierAsIssuer() throws ComponentInitializationException {
        addAssertions();
        final AuthnRequest request = SAML2ActionTestingSupport.buildAuthnRequest();
        final NameIDPolicy policy = policyBuilder.buildObject();
        policy.setFormat(NameID.PERSISTENT);
        policy.setSPNameQualifier("foo");
        request.setNameIDPolicy(policy);
        prc.ensureInboundMessageContext().setMessage(request);
        
        action.initialize();
        action.execute(prc);
        ActionTestingSupport.assertEvent(prc, SAMLEventIds.INVALID_NAMEID_POLICY);

        Assertion assertion = ((Response) prc.ensureOutboundMessageContext().ensureMessage()).getAssertions().get(0);
        Subject subject = assertion.getSubject();
        Assert.assertNull(subject);
        
        final Issuer issuer = request.getIssuer();
        assert issuer != null;
        policy.setSPNameQualifier(issuer.getValue());
        action.execute(prc);
        ActionTestingSupport.assertProceedEvent(prc);
        
        assertion = ((Response) prc.ensureOutboundMessageContext().ensureMessage()).getAssertions().get(0);
        subject = assertion.getSubject();
        assert subject != null;
        final NameID nameID = subject.getNameID();
        assert nameID != null;
        Assert.assertEquals(nameID.getValue(), "baf");
        Assert.assertEquals(nameID.getFormat(), NameID.PERSISTENT);
    }
    
    @Test void testAffiliation() throws ComponentInitializationException {
        addAssertions();
        final AuthnRequest request = SAML2ActionTestingSupport.buildAuthnRequest();
        final NameIDPolicy policy = policyBuilder.buildObject();
        policy.setFormat(NameID.UNSPECIFIED);
        policy.setSPNameQualifier("foo");
        request.setNameIDPolicy(policy);
        prc.ensureInboundMessageContext().setMessage(request);
        
        final AffiliationNameIDPolicyPredicate predicate = new AffiliationNameIDPolicyPredicate();
        predicate.setMetadataResolver(metadataResolver);
        predicate.setRequesterIdLookupStrategy(new AddNameIDToSubjects.RequesterIdFromIssuerFunction());
        predicate.setObjectLookupStrategy(new AddNameIDToSubjects.NameIDPolicyLookupFunction());
        predicate.initialize();
        action.setNameIDPolicyPredicate(predicate);
        action.initialize();
        action.execute(prc);
        ActionTestingSupport.assertEvent(prc, SAMLEventIds.INVALID_NAMEID_POLICY);

        Assertion assertion = ((Response) prc.ensureOutboundMessageContext().ensureMessage()).getAssertions().get(0);
        Subject subject = assertion.getSubject();
        Assert.assertNull(subject);
        
        policy.setFormat(NameID.PERSISTENT);
        policy.setSPNameQualifier("http://affiliation.example.org");
        action.execute(prc);
        ActionTestingSupport.assertProceedEvent(prc);
        
        assertion = ((Response) prc.ensureOutboundMessageContext().ensureMessage()).getAssertions().get(0);
        subject = assertion.getSubject();
        assert subject != null;
        final NameID nameID = subject.getNameID();
        assert nameID != null;
        Assert.assertEquals(nameID.getValue(), "baf");
        Assert.assertEquals(nameID.getFormat(), NameID.PERSISTENT);
    }
    
    @Test void testArbitraryFormat() throws ComponentInitializationException {
        addAssertions();
        
        action.initialize();
        action.execute(prc);
        ActionTestingSupport.assertProceedEvent(prc);
        
        Assertion assertion = ((Response) prc.ensureOutboundMessageContext().ensureMessage()).getAssertions().get(0);
        Subject subject = assertion.getSubject();
        Assert.assertNull(subject);

        assertion = ((Response) prc.ensureOutboundMessageContext().ensureMessage()).getAssertions().get(1);
        subject = assertion.getSubject();
        Assert.assertNull(subject);
    }
    
    @Test void testSingleGenerator() throws ComponentInitializationException {
        addAssertions();
        
        action.setFormatLookupStrategy(new X509FormatLookupStrategy());
        action.initialize();
        action.execute(prc);
        ActionTestingSupport.assertProceedEvent(prc);
        
        Assertion assertion = ((Response) prc.ensureOutboundMessageContext().ensureMessage()).getAssertions().get(0);
        Subject subject = assertion.getSubject();
        assert subject != null;
        NameID nameID = subject.getNameID();
        assert nameID != null;
        Assert.assertEquals(nameID.getValue(), "foo");
        Assert.assertEquals(nameID.getFormat(), NameID.X509_SUBJECT);

        assertion = ((Response) prc.ensureOutboundMessageContext().ensureMessage()).getAssertions().get(1);
        subject = assertion.getSubject();
        assert subject != null;
        nameID = subject.getNameID();
        assert nameID != null;
        Assert.assertEquals(nameID.getValue(), "foo");
        Assert.assertEquals(nameID.getFormat(), NameID.X509_SUBJECT);
    }

    @Test void testMultipleGenerators() throws ComponentInitializationException {
        addAssertions();
        
        action.setFormatLookupStrategy(new EmailFormatLookupStrategy());
        action.initialize();
        action.execute(prc);
        ActionTestingSupport.assertProceedEvent(prc);
        
        Assertion assertion = ((Response) prc.ensureOutboundMessageContext().ensureMessage()).getAssertions().get(0);
        Subject subject = assertion.getSubject();
        assert subject != null;
        NameID nameID = subject.getNameID();
        assert nameID != null;
        Assert.assertEquals(nameID.getValue(), "baz");
        Assert.assertEquals(nameID.getFormat(), NameID.EMAIL);

        assertion = ((Response) prc.ensureOutboundMessageContext().ensureMessage()).getAssertions().get(1);
        subject = assertion.getSubject();
        assert subject != null;
        nameID = subject.getNameID();
        assert nameID != null;
        Assert.assertEquals(nameID.getValue(), "baz");
        Assert.assertEquals(nameID.getFormat(), NameID.EMAIL);
    }
    
    /** Set up the test message with some assertions. */
    private void addAssertions() {
        final Response response = SAML2ActionTestingSupport.buildResponse();
        response.getAssertions().add(SAML2ActionTestingSupport.buildAssertion());
        response.getAssertions().add(SAML2ActionTestingSupport.buildAssertion());
        prc.ensureOutboundMessageContext().setMessage(response);
    }
    
    private class MockSAML2NameIDGenerator extends AbstractSAML2NameIDGenerator {

        private final String identifier;
        
        public MockSAML2NameIDGenerator(@Nonnull final String id) {
            setId("test");
            setDefaultIdPNameQualifierLookupStrategy(new Function<ProfileRequestContext,String>() {
                @Override
                public String apply(ProfileRequestContext input) {
                    return NAME_QUALIFIER;
                }
            });
            identifier = id;
        }
        
        /** {@inheritDoc} */
        @Override
        protected String getIdentifier(ProfileRequestContext profileRequestContext) throws SAMLException {
            return identifier;
        }
    }
    
    private class X509FormatLookupStrategy implements Function<ProfileRequestContext, List<String>> {

        /** {@inheritDoc} */
        @Override
        public List<String> apply(ProfileRequestContext input) {
            return Arrays.asList(NameID.WIN_DOMAIN_QUALIFIED, NameID.X509_SUBJECT);
        }
    }

    private class EmailFormatLookupStrategy implements Function<ProfileRequestContext, List<String>> {

        /** {@inheritDoc} */
        @Override
        public List<String> apply(ProfileRequestContext input) {
            return Arrays.asList(NameID.WIN_DOMAIN_QUALIFIED, NameID.EMAIL);
        }
    }
    
}