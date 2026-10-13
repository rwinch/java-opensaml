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

package org.opensaml.xmlsec.keyinfo;

import java.math.BigInteger;
import java.security.KeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAParameterSpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.LinkedList;
import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHPublicKeySpec;

import org.apache.xml.security.utils.XMLUtils;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.opensaml.core.xml.XMLObjectBuilder;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.crypto.JCAConstants;
import org.opensaml.security.crypto.dh.DHSupport;
import org.opensaml.security.crypto.ec.ECSupport;
import org.opensaml.security.x509.X509Support;
import org.opensaml.xmlsec.algorithm.AlgorithmSupport;
import org.opensaml.xmlsec.encryption.DHKeyValue;
import org.opensaml.xmlsec.encryption.Generator;
import org.opensaml.xmlsec.encryption.Public;
import org.opensaml.xmlsec.signature.DEREncodedKeyValue;
import org.opensaml.xmlsec.signature.DSAKeyValue;
import org.opensaml.xmlsec.signature.ECKeyValue;
import org.opensaml.xmlsec.signature.Exponent;
import org.opensaml.xmlsec.signature.G;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.KeyName;
import org.opensaml.xmlsec.signature.KeyValue;
import org.opensaml.xmlsec.signature.Modulus;
import org.opensaml.xmlsec.signature.NamedCurve;
import org.opensaml.xmlsec.signature.P;
import org.opensaml.xmlsec.signature.Q;
import org.opensaml.xmlsec.signature.RSAKeyValue;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.X509Digest;
import org.opensaml.xmlsec.signature.X509IssuerName;
import org.opensaml.xmlsec.signature.X509IssuerSerial;
import org.opensaml.xmlsec.signature.X509SKI;
import org.opensaml.xmlsec.signature.X509SerialNumber;
import org.opensaml.xmlsec.signature.X509SubjectName;
import org.opensaml.xmlsec.signature.Y;
import org.slf4j.Logger;

import com.google.common.base.Strings;

import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.annotation.constraint.NotLive;
import net.shibboleth.shared.annotation.constraint.Unmodifiable;
import net.shibboleth.shared.codec.DecodingException;
import net.shibboleth.shared.codec.EncodingException;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.primitive.LoggerFactory;

/**
 * Utility class for working with data inside a KeyInfo object.
 * 
 * Methods are provided for converting the representation stored in the XMLTooling KeyInfo to Java java.security native
 * types, and for storing these Java native types inside a KeyInfo.
 */
public final class KeyInfoSupport {
    
    /** Logger. */
    @Nonnull private static final Logger LOG = LoggerFactory.getLogger(KeyInfoSupport.class);

    /** Encoder used to produce chunked Base64 output. */
    @Nonnull private static final Base64.Encoder CHUNKED_ENCODER = Base64.getMimeEncoder(76, new byte[] { '\n' });

    /**
     * Factory for {@link java.security.cert.X509Certificate} and {@link java.security.cert.X509CRL} creation.
     */
    @Nullable private static CertificateFactory x509CertFactory;

    /** Constructor. */
    private KeyInfoSupport() {

    }

    /**
     * Get the set of key names inside the specified {@link KeyInfo} as a list of strings.
     * 
     * @param keyInfo {@link KeyInfo} to retrieve key names from
     * 
     * @return a list of key name strings
     */
    @Nonnull @Unmodifiable @NotLive public static List<String> getKeyNames(@Nullable final KeyInfo keyInfo) {
        final List<String> keynameList = new LinkedList<>();

        if (keyInfo == null) {
            return keynameList;
        }

        final List<KeyName> keyNames = keyInfo.getKeyNames();
        for (final KeyName keyName : keyNames) {
            if (keyName.getValue() != null) {
                keynameList.add(keyName.getValue());
            }
        }

        return keynameList;
    }

    /**
     * Add a new {@link KeyName} value to a KeyInfo.
     * 
     * @param keyInfo the KeyInfo to which to add the new value
     * @param keyNameValue the new key name value to add
     */
    public static void addKeyName(@Nonnull final KeyInfo keyInfo, @Nullable final String keyNameValue) {
        Constraint.isNotNull(keyInfo, "KeyInfo cannot be null");

        final XMLObjectBuilder<KeyName> keyNameBuilder =
                XMLObjectProviderRegistrySupport.getBuilderFactory().ensureBuilder(KeyName.DEFAULT_ELEMENT_NAME);
        final KeyName keyName = keyNameBuilder.buildObject(KeyName.DEFAULT_ELEMENT_NAME);
        keyName.setValue(keyNameValue);
        keyInfo.getKeyNames().add(keyName);
    }

    /**
     * Get a list of the Java {@link java.security.cert.X509Certificate} within the given KeyInfo.
     * 
     * @param keyInfo key info to extract the certificates from
     * 
     * @return a list of Java {@link java.security.cert.X509Certificate}s
     * 
     * @throws CertificateException thrown if there is a problem converting the X509 data into
     *             {@link java.security.cert.X509Certificate}s.
     */
    @Nonnull @Unmodifiable @NotLive public static List<X509Certificate> getCertificates(@Nullable final KeyInfo keyInfo)
            throws CertificateException {
        final List<X509Certificate> certList = new LinkedList<>();

        if (keyInfo == null) {
            return certList;
        }

        final List<X509Data> x509Datas = keyInfo.getX509Datas();
        for (final X509Data x509Data : x509Datas) {
            certList.addAll(getCertificates(x509Data));
        }

        return certList;
    }

    /**
     * Get a list of the Java {@link java.security.cert.X509Certificate} within the given {@link X509Data}.
     * 
     * @param x509Data {@link X509Data} from which to extract the certificate
     * 
     * @return a list of Java {@link java.security.cert.X509Certificate}s
     * 
     * @throws CertificateException thrown if there is a problem converting the X509 data into
     *             {@link java.security.cert.X509Certificate}s.
     */
    @Nonnull @Unmodifiable @NotLive public static List<X509Certificate> getCertificates(
            @Nullable final X509Data x509Data) throws CertificateException {
        final List<X509Certificate> certList = new LinkedList<>();

        if (x509Data == null) {
            return certList;
        }

        for (final org.opensaml.xmlsec.signature.X509Certificate xmlCert : x509Data.getX509Certificates()) {
            final X509Certificate newCert = getCertificate(xmlCert);
            if (newCert != null) {
                certList.add(newCert);
            }
        }

        return certList;
    }

    /**
     * Convert an {@link org.opensaml.xmlsec.signature.X509Certificate} into a native Java representation.
     * 
     * @param xmlCert an {@link org.opensaml.xmlsec.signature.X509Certificate}
     * 
     * @return a {@link java.security.cert.X509Certificate}
     * 
     * @throws CertificateException thrown if there is a problem converting the X509 data into
     *             {@link java.security.cert.X509Certificate}s.
     */
    @Nullable public static X509Certificate getCertificate(
            @Nullable final org.opensaml.xmlsec.signature.X509Certificate xmlCert) throws CertificateException {

        final String certVal = xmlCert != null ? xmlCert.getValue() : null;
        if (certVal == null) {
            return null;
        }

        return X509Support.decodeCertificate(certVal);
    }

    /**
     * Get a list of the Java {@link java.security.cert.X509CRL}s within the given {@link KeyInfo}.
     * 
     * @param keyInfo the {@link KeyInfo} to extract the CRLs from
     * 
     * @return a list of Java {@link java.security.cert.X509CRL}s
     * 
     * @throws CRLException thrown if there is a problem converting the CRL data into {@link java.security.cert.X509CRL}
     *             s
     */
    @Nonnull @Unmodifiable @NotLive public static List<X509CRL> getCRLs(
            @Nullable final KeyInfo keyInfo) throws CRLException {
        final List<X509CRL> crlList = new LinkedList<>();

        if (keyInfo == null) {
            return crlList;
        }

        final List<X509Data> x509Datas = keyInfo.getX509Datas();
        for (final X509Data x509Data : x509Datas) {
            crlList.addAll(getCRLs(x509Data));
        }

        return crlList;
    }

    /**
     * Get a list of the Java {@link java.security.cert.X509CRL}s within the given {@link X509Data}.
     * 
     * @param x509Data {@link X509Data} to extract the CRLs from
     * 
     * @return a list of Java {@link java.security.cert.X509CRL}s
     * 
     * @throws CRLException thrown if there is a problem converting the CRL data into {@link java.security.cert.X509CRL}
     *             s
     */
    @Nonnull @Unmodifiable @NotLive public static List<X509CRL> getCRLs(
            @Nullable final X509Data x509Data) throws CRLException {
        final List<X509CRL> crlList = new LinkedList<>();

        if (x509Data == null) {
            return crlList;
        }

        for (final org.opensaml.xmlsec.signature.X509CRL xmlCRL : x509Data.getX509CRLs()) {
            final X509CRL newCRL = getCRL(xmlCRL);
            if (newCRL != null) {
                crlList.add(newCRL);
            }
        }

        return crlList;
    }

    /**
     * Convert an {@link org.opensaml.xmlsec.signature.X509CRL} into a native Java representation.
     * 
     * @param xmlCRL object to extract the CRL from
     * 
     * @return a native Java {@link java.security.cert.X509CRL} object
     * 
     * @throws CRLException thrown if there is a problem converting the CRL data into {@link java.security.cert.X509CRL}
     */
    @Nullable public static X509CRL getCRL(@Nullable final org.opensaml.xmlsec.signature.X509CRL xmlCRL)
            throws CRLException {

        final String crlVal = xmlCRL != null ? xmlCRL.getValue() : null;
        if (crlVal == null) {
            return null;
        }

        try {
            return X509Support.decodeCRL(crlVal);
        } catch (final CertificateException e) {
            throw new CRLException("Certificate error attempting to decode CRL", e);
        }
    }

    /**
     * Converts a native Java {@link java.security.cert.X509Certificate} into the corresponding XMLObject and stores it
     * in a {@link KeyInfo} in the first {@link X509Data} element. The X509Data element will be created if necessary.
     * 
     * @param keyInfo the {@link KeyInfo} object into which to add the certificate
     * @param cert the Java {@link java.security.cert.X509Certificate} to add
     * @throws CertificateEncodingException thrown when there is an error converting the Java certificate representation
     *             to the XMLObject representation
     */
    public static void addCertificate(@Nonnull final KeyInfo keyInfo, @Nonnull final X509Certificate cert)
            throws CertificateEncodingException {
        Constraint.isNotNull(keyInfo, "KeyInfo cannot be null");
        
        final X509Data x509Data;
        if (keyInfo.getX509Datas().size() == 0) {
            final XMLObjectBuilder<X509Data> x509DataBuilder =
                    XMLObjectProviderRegistrySupport.getBuilderFactory().ensureBuilder(
                            X509Data.DEFAULT_ELEMENT_NAME);
            x509Data = x509DataBuilder.buildObject(X509Data.DEFAULT_ELEMENT_NAME);
            keyInfo.getX509Datas().add(x509Data);
        } else {
            x509Data = keyInfo.getX509Datas().get(0);
        }
        x509Data.getX509Certificates().add(buildX509Certificate(cert));
    }

    /**
     * Converts a native Java {@link java.security.cert.X509CRL} into the corresponding XMLObject and stores it in a
     * {@link KeyInfo} in the first {@link X509Data} element. The X509Data element will be created if necessary.
     * 
     * @param keyInfo the {@link KeyInfo} object into which to add the CRL
     * @param crl the Java {@link java.security.cert.X509CRL} to add
     * @throws CRLException thrown when there is an error converting the Java CRL representation to the XMLObject
     *             representation
     */
    public static void addCRL(@Nonnull final KeyInfo keyInfo, @Nonnull final X509CRL crl) throws CRLException {
        Constraint.isNotNull(keyInfo, "KeyInfo cannot be null");
        
        final X509Data x509Data;
        if (keyInfo.getX509Datas().size() == 0) {
            final XMLObjectBuilder<X509Data> x509DataBuilder =
                    XMLObjectProviderRegistrySupport.getBuilderFactory().<X509Data>ensureBuilder(
                            X509Data.DEFAULT_ELEMENT_NAME);
            x509Data = x509DataBuilder.buildObject(X509Data.DEFAULT_ELEMENT_NAME);
            keyInfo.getX509Datas().add(x509Data);
        } else {
            x509Data = keyInfo.getX509Datas().get(0);
        }
        x509Data.getX509CRLs().add(buildX509CRL(crl));
    }

    /**
     * Builds an {@link org.opensaml.xmlsec.signature.X509Certificate} XMLObject from a native Java
     * {@link java.security.cert.X509Certificate}.
     * 
     * @param cert the Java {@link java.security.cert.X509Certificate} to convert
     * @return a {@link org.opensaml.xmlsec.signature.X509Certificate} XMLObject
     * @throws CertificateEncodingException thrown when there is an error converting the Java certificate representation
     *             to the XMLObject representation
     */
    @Nonnull public static org.opensaml.xmlsec.signature.X509Certificate
            buildX509Certificate(final X509Certificate cert) throws CertificateEncodingException {
        Constraint.isNotNull(cert, "X.509 certificate cannot be null");
        
       
        final XMLObjectBuilder<org.opensaml.xmlsec.signature.X509Certificate> xmlCertBuilder =
                    XMLObjectProviderRegistrySupport.getBuilderFactory().ensureBuilder(
                            org.opensaml.xmlsec.signature.X509Certificate.DEFAULT_ELEMENT_NAME);
        final org.opensaml.xmlsec.signature.X509Certificate xmlCert =
                xmlCertBuilder.buildObject(org.opensaml.xmlsec.signature.X509Certificate.DEFAULT_ELEMENT_NAME);
        
        xmlCert.setValue(CHUNKED_ENCODER.encodeToString(cert.getEncoded()));  
        return xmlCert;
        
    }

    /**
     * Builds an {@link org.opensaml.xmlsec.signature.X509CRL} XMLObject from a native Java
     * {@link java.security.cert.X509CRL}.
     * 
     * @param crl the Java {@link java.security.cert.X509CRL} to convert
     * @return a {@link org.opensaml.xmlsec.signature.X509CRL} XMLObject
     * @throws CRLException thrown when there is an error converting the Java CRL representation to the XMLObject
     *             representation
     */
    @Nonnull public static org.opensaml.xmlsec.signature.X509CRL buildX509CRL(final X509CRL crl) throws CRLException {
        Constraint.isNotNull(crl, "X.509 CRL cannot be null");
        
        final XMLObjectBuilder<org.opensaml.xmlsec.signature.X509CRL> xmlCRLBuilder =
                    XMLObjectProviderRegistrySupport.getBuilderFactory().ensureBuilder(
                            org.opensaml.xmlsec.signature.X509CRL.DEFAULT_ELEMENT_NAME);
        final org.opensaml.xmlsec.signature.X509CRL xmlCRL =
                xmlCRLBuilder.buildObject(org.opensaml.xmlsec.signature.X509CRL.DEFAULT_ELEMENT_NAME);
        
        xmlCRL.setValue(CHUNKED_ENCODER.encodeToString(crl.getEncoded()));
        return xmlCRL;
    }

    /**
     * Build an {@link X509SubjectName} containing a given subject name.
     * 
     * @param subjectName the name content
     * @return the new X509SubjectName
     */
    @Nonnull public static X509SubjectName buildX509SubjectName(@Nullable final String subjectName) {
        final XMLObjectBuilder<X509SubjectName> xmlSubjectNameBuilder =
                XMLObjectProviderRegistrySupport.getBuilderFactory().ensureBuilder(
                        X509SubjectName.DEFAULT_ELEMENT_NAME);
        final X509SubjectName xmlSubjectName = xmlSubjectNameBuilder.buildObject(X509SubjectName.DEFAULT_ELEMENT_NAME);
        xmlSubjectName.setValue(subjectName);
        return xmlSubjectName;
    }

    /**
     * Build an {@link X509IssuerSerial} containing a given issuer name and serial number.
     * 
     * @param issuerName the name content
     * @param serialNumber the serial number content
     * @return the new X509IssuerSerial
     */
    @Nonnull public static X509IssuerSerial buildX509IssuerSerial(@Nullable final String issuerName,
            @Nullable final BigInteger serialNumber) {
        final XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
        
        final XMLObjectBuilder<X509IssuerName> xmlIssuerNameBuilder =
                builderFactory.ensureBuilder(X509IssuerName.DEFAULT_ELEMENT_NAME);
        final X509IssuerName xmlIssuerName = xmlIssuerNameBuilder.buildObject(X509IssuerName.DEFAULT_ELEMENT_NAME);
        xmlIssuerName.setValue(issuerName);

        final XMLObjectBuilder<X509SerialNumber> xmlSerialNumberBuilder =
                builderFactory.ensureBuilder(X509SerialNumber.DEFAULT_ELEMENT_NAME);
        final X509SerialNumber xmlSerialNumber =
                xmlSerialNumberBuilder.buildObject(X509SerialNumber.DEFAULT_ELEMENT_NAME);
        xmlSerialNumber.setValue(serialNumber);

        final XMLObjectBuilder<X509IssuerSerial> xmlIssuerSerialBuilder =
                builderFactory.ensureBuilder(X509IssuerSerial.DEFAULT_ELEMENT_NAME);
        final X509IssuerSerial xmlIssuerSerial =
                xmlIssuerSerialBuilder.buildObject(X509IssuerSerial.DEFAULT_ELEMENT_NAME);
        xmlIssuerSerial.setX509IssuerName(xmlIssuerName);
        xmlIssuerSerial.setX509SerialNumber(xmlSerialNumber);

        return xmlIssuerSerial;
    }

    /**
     * Build an {@link X509SKI} containing the subject key identifier extension value contained within a certificate.
     * 
     * @param javaCert the Java X509Certificate from which to extract the subject key identifier value.
     * @return a new X509SKI object, or null if the certificate did not contain the subject key identifier extension, 
     *         or the subject key identifier binary can not be base64-encoded.
     * @throws SecurityException if there is a problem building the subject key identifier. 
     */
    @Nullable public static X509SKI buildX509SKI(@Nonnull final X509Certificate javaCert) throws SecurityException {
        final byte[] skiPlainValue = X509Support.getSubjectKeyIdentifier(javaCert);
        
        if (skiPlainValue == null || skiPlainValue.length == 0) {
            return null;
        }

        final XMLObjectBuilder<X509SKI> xmlSKIBuilder =
                XMLObjectProviderRegistrySupport.getBuilderFactory().ensureBuilder(X509SKI.DEFAULT_ELEMENT_NAME);
        final X509SKI xmlSKI = xmlSKIBuilder.buildObject(X509SKI.DEFAULT_ELEMENT_NAME);
        
        
        xmlSKI.setValue(CHUNKED_ENCODER.encodeToString(skiPlainValue));
        return xmlSKI;
    }

    /**
     * Build an {@link X509Digest} containing the digest of the specified certificate.
     * 
     * @param javaCert the Java X509Certificate to digest
     * @param algorithmURI  digest algorithm URI
     * @return a new X509Digest object
     * @throws NoSuchAlgorithmException if the algorithm specified cannot be used
     * @throws CertificateEncodingException if the certificate cannot be encoded
     */
    @Nonnull public static X509Digest buildX509Digest(@Nonnull final X509Certificate javaCert,
            @Nonnull final String algorithmURI) throws NoSuchAlgorithmException, CertificateEncodingException {
        Constraint.isNotNull(javaCert, "Certificate cannot be null");

        final String jceAlg = AlgorithmSupport.getAlgorithmID(algorithmURI);
        if (jceAlg == null) {
            throw new NoSuchAlgorithmException("No JCE algorithm found for " + algorithmURI);
        }
        final MessageDigest md = MessageDigest.getInstance(jceAlg);
        final byte[] hash = md.digest(javaCert.getEncoded());
        
        final XMLObjectBuilder<X509Digest> builder =
                XMLObjectProviderRegistrySupport.getBuilderFactory().ensureBuilder(X509Digest.DEFAULT_ELEMENT_NAME);
        final X509Digest xmlDigest = builder.buildObject(X509Digest.DEFAULT_ELEMENT_NAME);
        xmlDigest.setAlgorithm(algorithmURI);
        
        xmlDigest.setValue(CHUNKED_ENCODER.encodeToString(hash));
        return xmlDigest;
    }    
    
    /**
     * Converts a Java RSA, EC, DSA or DH public key into the corresponding XMLObject and stores it in a
     * {@link KeyInfo} in a new {@link KeyValue} element.
     * 
     * <p>
     * As input, only supports {@link PublicKey} instances which are:
     * </p>
     * <ul>
     * <li>{@link java.security.interfaces.RSAPublicKey}</li>
     * <li>{@link java.security.interfaces.ECPublicKey}</li>
     * <li>{@link java.security.interfaces.DSAPublicKey}</li>
     * <li>{@link javax.crypto.interfaces.DHPublicKey}</li>
     * </ul>
     * 
     * @param keyInfo the {@link KeyInfo} element to which to add the key
     * @param pk the native Java {@link PublicKey} to add
     * @throws EncodingException if base64 encoding the components of the public key <code>pk</code> fails
     */
    public static void addPublicKey(@Nonnull final KeyInfo keyInfo, @Nonnull final PublicKey pk) 
            throws EncodingException {
        Constraint.isNotNull(keyInfo, "KeyInfo cannot be null");
        
        final XMLObjectBuilder<KeyValue> keyValueBuilder =
                XMLObjectProviderRegistrySupport.getBuilderFactory().ensureBuilder(KeyValue.DEFAULT_ELEMENT_NAME);
        final KeyValue keyValue = keyValueBuilder.buildObject(KeyValue.DEFAULT_ELEMENT_NAME);

        if (pk instanceof RSAPublicKey) {
            keyValue.setRSAKeyValue(buildRSAKeyValue((RSAPublicKey) pk));
        } else if (pk instanceof ECPublicKey) {
            keyValue.setECKeyValue(buildECKeyValue((ECPublicKey) pk));
        } else if (pk instanceof DSAPublicKey) {
            keyValue.setDSAKeyValue(buildDSAKeyValue((DSAPublicKey) pk));
        } else if (pk instanceof DHPublicKey) {
            keyValue.setDHKeyValue(buildDHKeyValue((DHPublicKey) pk));
        } else {
            final String type = pk.getClass().getName();
            throw new IllegalArgumentException("Saw unsupported public key type: " + type);
        }

        keyInfo.getKeyValues().add(keyValue);
    }
    
    /**
     * Builds a {@link DHKeyValue} XMLObject from the Java security DH public key type.
     * 
     * @param dhPubKey a native Java {@link DHPublicKey}
     * @return an {@link DHKeyValue} XMLObject
     * @throws EncodingException if the DH public key parameters can not be base64 encoded
     */
    @Nonnull public static DHKeyValue buildDHKeyValue(@Nonnull final DHPublicKey dhPubKey) 
            throws EncodingException {
        Constraint.isNotNull(dhPubKey, "DH public key cannot be null");
        
        final XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();

        final XMLObjectBuilder<DHKeyValue> dhKeyValueBuilder =
                builderFactory.ensureBuilder(DHKeyValue.DEFAULT_ELEMENT_NAME);
        final DHKeyValue dhKeyValue = dhKeyValueBuilder.buildObject(DHKeyValue.DEFAULT_ELEMENT_NAME);

        final XMLObjectBuilder<Generator> generatorBuilder =
                builderFactory.ensureBuilder(Generator.DEFAULT_ELEMENT_NAME);
        final XMLObjectBuilder<Public> publicBuilder = builderFactory.ensureBuilder(Public.DEFAULT_ELEMENT_NAME);
        final XMLObjectBuilder<org.opensaml.xmlsec.encryption.P> pBuilder =
                builderFactory.ensureBuilder(org.opensaml.xmlsec.encryption.P.DEFAULT_ELEMENT_NAME);
        final XMLObjectBuilder<org.opensaml.xmlsec.encryption.Q> qBuilder =
                builderFactory.ensureBuilder(org.opensaml.xmlsec.encryption.Q.DEFAULT_ELEMENT_NAME);
        
        final Public pub = publicBuilder.buildObject(Public.DEFAULT_ELEMENT_NAME);
        final Generator gen = generatorBuilder.buildObject(Generator.DEFAULT_ELEMENT_NAME);
        final org.opensaml.xmlsec.encryption.P p =
                pBuilder.buildObject(org.opensaml.xmlsec.encryption.P.DEFAULT_ELEMENT_NAME);

        pub.setValueBigInt(dhPubKey.getY());
        dhKeyValue.setPublic(pub);

        gen.setValueBigInt(dhPubKey.getParams().getG());
        dhKeyValue.setGenerator(gen);

        p.setValueBigInt(dhPubKey.getParams().getP());
        dhKeyValue.setP(p);

        // DHParameterSpec doesn't expose the Q param.  Also, it seems sometimes the ASN.1 encoded keys do not have
        // a Q param, which is a violation of RFC 3279, section 2.3.3. So we have to deal with the null case.
        // If it doesn't have Q, just emit without, even thought it violates the XML Encryption schema,
        // since we don't actually need it to construct a DHPublicKey key anyway.
        final BigInteger qValue = DHSupport.getPrimeQDomainParameter(dhPubKey);
        if (qValue != null) {
            final org.opensaml.xmlsec.encryption.Q q =
                    qBuilder.buildObject(org.opensaml.xmlsec.encryption.Q.DEFAULT_ELEMENT_NAME);
            q.setValueBigInt(qValue);
            dhKeyValue.setQ(q);
        }

        return dhKeyValue;
    }

    /**
     * Builds an {@link ECKeyValue} XMLObject from the Java security EC public key type.
     * 
     * <p>
     * Only curve parameters specified by a {@link NamedCurve} are supported.  Use of explicit
     * curve parameters will throw.
     * </p>
     * 
     * @param ecPubKey a naive java {@link ECPublicKey}
     * @return an {@link ECKeyValue} XMLObject
     * @throws EncodingException if the NamedCurve variant was not used, if the EC PublicKey value is invalid
     *                           or if the EC PublicKey value can not be Base64 encoded
     */
    @Nonnull public static ECKeyValue buildECKeyValue(@Nonnull final ECPublicKey ecPubKey) throws EncodingException {
        Constraint.isNotNull(ecPubKey, "EC public key cannot be null");
        
        final XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
        
        final ECKeyValue ecKeyValue = (ECKeyValue) builderFactory.ensureBuilder(ECKeyValue.DEFAULT_ELEMENT_NAME)
                .buildObject(ECKeyValue.DEFAULT_ELEMENT_NAME);
        
        final NamedCurve namedCurve = (NamedCurve) builderFactory.ensureBuilder(NamedCurve.DEFAULT_ELEMENT_NAME)
                .buildObject(NamedCurve.DEFAULT_ELEMENT_NAME);
        
        final org.opensaml.xmlsec.signature.PublicKey publicKey =
                (org.opensaml.xmlsec.signature.PublicKey) builderFactory.ensureBuilder(
                        org.opensaml.xmlsec.signature.PublicKey.DEFAULT_ELEMENT_NAME)
                .buildObject(org.opensaml.xmlsec.signature.PublicKey.DEFAULT_ELEMENT_NAME);
        
        final String uri = ECSupport.getNamedCurveURI(ecPubKey);
        if (uri == null) {
            // TODO EncdoingException doesn't really seem correct here, but we likely can't add a
            // new checked exception type in a minor release. I guess it's sort of "encoding" though ... 
            throw new EncodingException("Unable to obtain NamedCurve URI from ECPublicKey");
        }
        
        namedCurve.setURI(uri);
        ecKeyValue.setNamedCurve(namedCurve);
        
        publicKey.setValue(Base64.getEncoder().encodeToString(
                ECSupport.encodeECPointUncompressed(ecPubKey.getW(), ecPubKey.getParams().getCurve())));
        ecKeyValue.setPublicKey(publicKey);
        
        return ecKeyValue;
    }

    /**
     * Builds an {@link RSAKeyValue} XMLObject from the Java security RSA public key type.
     * 
     * @param rsaPubKey a native Java {@link RSAPublicKey}
     * @return an {@link RSAKeyValue} XMLObject
     * @throws EncodingException if the RSA public key modulus/exponent can not be base64 encoded
     */
    @Nonnull public static RSAKeyValue buildRSAKeyValue(@Nonnull final RSAPublicKey rsaPubKey) 
            throws EncodingException {
        Constraint.isNotNull(rsaPubKey, "RSA public key cannot be null");
        
        final XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
        
        final XMLObjectBuilder<RSAKeyValue> rsaKeyValueBuilder =
                builderFactory.ensureBuilder(RSAKeyValue.DEFAULT_ELEMENT_NAME);
        final RSAKeyValue rsaKeyValue = rsaKeyValueBuilder.buildObject(RSAKeyValue.DEFAULT_ELEMENT_NAME);
        
        final XMLObjectBuilder<Modulus> modulusBuilder = builderFactory.ensureBuilder(Modulus.DEFAULT_ELEMENT_NAME);
        final Modulus modulus = modulusBuilder.buildObject(Modulus.DEFAULT_ELEMENT_NAME);
        
        final XMLObjectBuilder<Exponent> exponentBuilder =
                builderFactory.ensureBuilder(Exponent.DEFAULT_ELEMENT_NAME);
        final Exponent exponent = exponentBuilder.buildObject(Exponent.DEFAULT_ELEMENT_NAME);

        modulus.setValueBigInt(rsaPubKey.getModulus());
        rsaKeyValue.setModulus(modulus);

        exponent.setValueBigInt(rsaPubKey.getPublicExponent());
        rsaKeyValue.setExponent(exponent);

        return rsaKeyValue;
    }

    /**
     * Builds a {@link DSAKeyValue} XMLObject from the Java security DSA public key type.
     * 
     * @param dsaPubKey a native Java {@link DSAPublicKey}
     * @return an {@link DSAKeyValue} XMLObject
     * @throws EncodingException if the DSA public key parameters can not be base64 encoded
     */
    @Nonnull public static DSAKeyValue buildDSAKeyValue(@Nonnull final DSAPublicKey dsaPubKey) 
            throws EncodingException {
        Constraint.isNotNull(dsaPubKey, "DSA public key cannot be null");
        
        final XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();

        final XMLObjectBuilder<DSAKeyValue> dsaKeyValueBuilder =
                builderFactory.ensureBuilder(DSAKeyValue.DEFAULT_ELEMENT_NAME);
        final DSAKeyValue dsaKeyValue = dsaKeyValueBuilder.buildObject(DSAKeyValue.DEFAULT_ELEMENT_NAME);

        final XMLObjectBuilder<Y> yBuilder = builderFactory.ensureBuilder(Y.DEFAULT_ELEMENT_NAME);
        final XMLObjectBuilder<G> gBuilder = builderFactory.ensureBuilder(G.DEFAULT_ELEMENT_NAME);
        final XMLObjectBuilder<P> pBuilder = builderFactory.ensureBuilder(P.DEFAULT_ELEMENT_NAME);
        final XMLObjectBuilder<Q> qBuilder = builderFactory.ensureBuilder(Q.DEFAULT_ELEMENT_NAME);
        
        final Y y = yBuilder.buildObject(Y.DEFAULT_ELEMENT_NAME);
        final G g = gBuilder.buildObject(G.DEFAULT_ELEMENT_NAME);
        final P p = pBuilder.buildObject(P.DEFAULT_ELEMENT_NAME);
        final Q q = qBuilder.buildObject(Q.DEFAULT_ELEMENT_NAME);

        y.setValueBigInt(dsaPubKey.getY());
        dsaKeyValue.setY(y);

        g.setValueBigInt(dsaPubKey.getParams().getG());
        dsaKeyValue.setG(g);

        p.setValueBigInt(dsaPubKey.getParams().getP());
        dsaKeyValue.setP(p);

        q.setValueBigInt(dsaPubKey.getParams().getQ());
        dsaKeyValue.setQ(q);

        return dsaKeyValue;
    }

    /**
     * Converts a Java public key into the corresponding XMLObject and stores it in a {@link KeyInfo} in a
     * new {@link DEREncodedKeyValue} element.
     * 
     * @param keyInfo the {@link KeyInfo} element to which to add the key
     * @param pk the native Java {@link PublicKey} to convert
     * @throws NoSuchAlgorithmException if the key type is unsupported
     * @throws InvalidKeySpecException if the key type does not support X.509 SPKI encoding
     */
    public static void addDEREncodedPublicKey(@Nonnull final KeyInfo keyInfo,
            @Nonnull final PublicKey pk) throws NoSuchAlgorithmException, InvalidKeySpecException {
        Constraint.isNotNull(keyInfo, "KeyInfo cannot be null");
        Constraint.isNotNull(pk, "Public key cannot be null");
        
        final XMLObjectBuilder<DEREncodedKeyValue> builder =
                XMLObjectProviderRegistrySupport.getBuilderFactory().ensureBuilder(
                        DEREncodedKeyValue.DEFAULT_ELEMENT_NAME);
        final DEREncodedKeyValue keyValue = builder.buildObject(DEREncodedKeyValue.DEFAULT_ELEMENT_NAME);
        
        final KeyFactory keyFactory = KeyFactory.getInstance(pk.getAlgorithm());
        final X509EncodedKeySpec keySpec = keyFactory.getKeySpec(pk, X509EncodedKeySpec.class);
        
        keyValue.setValue(CHUNKED_ENCODER.encodeToString(keySpec.getEncoded()));
        
        keyInfo.getDEREncodedKeyValues().add(keyValue);
    }
    
    /**
     * Extracts all the public keys within the given {@link KeyInfo}'s {@link KeyValue}s and
     * {@link DEREncodedKeyValue}s.
     * 
     * @param keyInfo {@link KeyInfo} to extract the keys out of
     * 
     * @return a list of native Java {@link PublicKey} objects
     * 
     * @throws KeyException thrown if the given key data can not be converted into {@link PublicKey}
     */
    @Nonnull public static List<PublicKey> getPublicKeys(@Nullable final KeyInfo keyInfo) throws KeyException {

        final List<PublicKey> keys = new LinkedList<>();

        if (keyInfo == null) {
            return keys;
        }

        for (final KeyValue keyDescriptor : keyInfo.getKeyValues()) {
            assert keyDescriptor != null;
            final PublicKey newKey = getKey(keyDescriptor);
            if (newKey != null) {
                keys.add(newKey);
            }
        }

        for (final DEREncodedKeyValue keyDescriptor : keyInfo.getDEREncodedKeyValues()) {
            assert keyDescriptor != null;
            final PublicKey newKey = getKey(keyDescriptor);
            if (newKey != null) {
                keys.add(newKey);
            }
        }        
        return keys;
    }

    /**
     * Extracts the DSA or RSA public key within the {@link KeyValue}.
     * 
     * @param keyValue the {@link KeyValue} to extract the key from
     * 
     * @return a native Java security {@link java.security.Key} object
     * 
     * @throws KeyException thrown if the given key data can not be converted into {@link PublicKey}
     */
    @Nullable public static PublicKey getKey(@Nonnull final KeyValue keyValue) throws KeyException {
        Constraint.isNotNull(keyValue, "KeyValue cannot be null");

        final DSAKeyValue dsa = keyValue.getDSAKeyValue();
        if (dsa != null) {
            return getDSAKey(dsa);
        }
        
        final RSAKeyValue rsa = keyValue.getRSAKeyValue();
        if (rsa != null) {
            return getRSAKey(rsa);
        }
        
        final ECKeyValue ec = keyValue.getECKeyValue();
        if (ec != null) {
            return getECKey(ec);
        }
        
        final DHKeyValue dh = keyValue.getDHKeyValue();
        if (dh != null) {
            return getDHKey(dh);
        }
        
        return null;
    }

    /**
     * Builds an EC key from an {@link ECKeyValue} element.
     * 
     * @param keyDescriptor the {@link ECKeyValue} key descriptor
     * 
     * @return a new {@link ECPublicKey} instance of {@link PublicKey}
     * 
     * @throws KeyException thrown if the key algorithm is not supported by the JCE or the key spec does not contain
     *             valid information
     */
    @Nonnull public static PublicKey getECKey(@Nonnull final ECKeyValue keyDescriptor) throws KeyException {
        
        final NamedCurve namedCurve = keyDescriptor.getNamedCurve();
        if (namedCurve == null || namedCurve.getURI() == null) {
            throw new KeyException("Only ECKeyValue NamedCurve representation is supported");
        }
        
        final String curveURI = namedCurve.getURI();
        if (curveURI == null) {
            throw new KeyException("Only ECKeyValue NamedCurve representation is supported");
        }
        
        final ECParameterSpec ecParams = ECSupport.getParameterSpecForURI(curveURI);
        if (ecParams == null) {
            throw new KeyException("Could not resolve ECParametersSpec for NamedCurve URI: " + curveURI);
        }

        final org.opensaml.xmlsec.signature.PublicKey pub = keyDescriptor.getPublicKey();
        final String pubval = pub != null ? pub.getValue() : null;
        if (pubval == null) {
            throw new KeyException("Could not obtain public key value");
        }
        
        final byte[] encodedPoint;
        try {
            encodedPoint = Base64.getMimeDecoder().decode(pubval);
        } catch (final IllegalArgumentException e) {
            throw new KeyException("Error Base64 decoding ECKeyValue PublicKey ECPoint", e);
        }
        
        final ECPoint ecPoint = ECSupport.decodeECPoint(encodedPoint, ecParams.getCurve());
        
        final ECPublicKeySpec keySpec = new ECPublicKeySpec(ecPoint, ecParams);
        
        return buildKey(keySpec, JCAConstants.KEY_ALGO_EC);
        
    }
    
    /**
     * Builds a DH key from a {@link DHKeyValue} element. The element must contain values for all required DH public
     * key parameters, including values for shared key family values P, Q and G (aka Generator).
     * 
     * @param keyDescriptor the {@link DHKeyValue} key descriptor
     * 
     * @return a new {@link DHPublicKey} instance of {@link PublicKey}
     * 
     * @throws KeyException thrown if the key algorithm is not supported by the JCE or the key spec does not contain
     *             valid information
     */
    @Nonnull public static PublicKey getDHKey(@Nonnull final DHKeyValue keyDescriptor) throws KeyException {
        if (!hasCompleteDHParams(keyDescriptor)) {
            throw new KeyException("DHKeyValue element did not contain at least one of DH parameters P, Q or G");
        }

        final Generator gen = keyDescriptor.getGenerator();
        final org.opensaml.xmlsec.encryption.P pComp = keyDescriptor.getP();
        final Public pub = keyDescriptor.getPublic();
        
        assert gen != null;
        assert pComp != null;
        
        final BigInteger gComponent = gen.getValueBigInt();
        final BigInteger pComponent = pComp.getValueBigInt();
        // Note: Java doesn't need or even accept the prime Q component, so don't bother to parse it

        final BigInteger publicComponent = pub != null ? pub.getValueBigInt() : null;

        final DHPublicKeySpec keySpec = new DHPublicKeySpec(publicComponent, pComponent, gComponent);
        return buildKey(keySpec, JCAConstants.KEY_ALGO_DIFFIE_HELLMAN);
    }
    
    /**
     * Check whether the specified {@link DHKeyValue} element has the all optional DH values which can be shared
     * amongst many keys in a DH "key family", and are presumed to be known from context.
     * 
     * @param keyDescriptor the {@link DHKeyValue} element to check
     * @return true if all parameters are present and non-empty, false otherwise
     */
    public static boolean hasCompleteDHParams(@Nullable final DHKeyValue keyDescriptor) {
        if (keyDescriptor == null) {
            return false;
        }
        
        final Generator gen = keyDescriptor.getGenerator();
        final org.opensaml.xmlsec.encryption.P pComp = keyDescriptor.getP();
        
        if (gen == null || Strings.isNullOrEmpty(gen.getValue())
                || pComp == null || Strings.isNullOrEmpty(pComp.getValue())
                // Note: Java doesn't need or even accept the prime Q component.  So even though it's
                // required per the schema, relax the check here and don't require.
                ) {
            return false;
        }
        
        return true;
    }

    /**
     * Builds an DSA key from a {@link DSAKeyValue} element. The element must contain values for all required DSA public
     * key parameters, including values for shared key family values P, Q and G.
     * 
     * @param keyDescriptor the {@link DSAKeyValue} key descriptor
     * 
     * @return a new {@link DSAPublicKey} instance of {@link PublicKey}
     * 
     * @throws KeyException thrown if the key algorithm is not supported by the JCE or the key spec does not contain
     *             valid information
     */
    @Nonnull public static PublicKey getDSAKey(@Nonnull final DSAKeyValue keyDescriptor) throws KeyException {
        if (!hasCompleteDSAParams(keyDescriptor)) {
            throw new KeyException("DSAKeyValue element did not contain at least one of DSA parameters P, Q or G");
        }
        
        final G gComp = keyDescriptor.getG();
        final P pComp = keyDescriptor.getP();
        final Q qComp = keyDescriptor.getQ();

        assert gComp != null;
        assert pComp != null;
        assert qComp != null;
        
        final BigInteger gComponent = gComp.getValueBigInt();
        final BigInteger pComponent = pComp.getValueBigInt();
        final BigInteger qComponent = qComp.getValueBigInt();

        final DSAParams dsaParams = new DSAParameterSpec(pComponent, qComponent, gComponent);
        return getDSAKey(keyDescriptor, dsaParams);
    }

    /**
     * Builds a DSA key from an {@link DSAKeyValue} element and the supplied Java {@link DSAParams}, which supplies key
     * material from a shared key family.
     * 
     * @param keyDescriptor the {@link DSAKeyValue} key descriptor
     * @param dsaParams the {@link DSAParams} DSA key family parameters
     * 
     * @return a new {@link DSAPublicKey} instance of {@link PublicKey}
     * 
     * @throws KeyException thrown if the key algorithm is not supported by the JCE or the key spec does not contain
     *             valid information
     */
    @Nonnull public static PublicKey getDSAKey(@Nonnull final DSAKeyValue keyDescriptor,
            @Nonnull final DSAParams dsaParams) throws KeyException {
        Constraint.isNotNull(keyDescriptor, "DSAKeyValue cannot be null");
        Constraint.isNotNull(dsaParams, "DSAParams cannot be null");
        
        final Y yComponent = keyDescriptor.getY();

        final DSAPublicKeySpec keySpec =
                new DSAPublicKeySpec(yComponent != null ? yComponent.getValueBigInt() : null,
                        dsaParams.getP(), dsaParams.getQ(), dsaParams.getG());
        return buildKey(keySpec, JCAConstants.KEY_ALGO_DSA);
    }

    /**
     * Check whether the specified {@link DSAKeyValue} element has the all optional DSA values which can be shared
     * amongst many keys in a DSA "key family", and are presumed to be known from context.
     * 
     * @param keyDescriptor the {@link DSAKeyValue} element to check
     * @return true if all parameters are present and non-empty, false otherwise
     */
    public static boolean hasCompleteDSAParams(@Nullable final DSAKeyValue keyDescriptor) {
        
        if (keyDescriptor == null) {
            return false;
        }
        
        final G gComp = keyDescriptor.getG();
        final P pComp = keyDescriptor.getP();
        final Q qComp = keyDescriptor.getQ();
        
        if (gComp == null || Strings.isNullOrEmpty(gComp.getValue())
                || pComp == null || Strings.isNullOrEmpty(pComp.getValue())
                || qComp == null || Strings.isNullOrEmpty(qComp.getValue())) {
            return false;
        }
        
        return true;
    }

    /**
     * Builds an RSA key from an {@link RSAKeyValue} element.
     * 
     * @param keyDescriptor the {@link RSAKeyValue} key descriptor
     * 
     * @return a new {@link RSAPublicKey} instance of {@link PublicKey}
     * 
     * @throws KeyException thrown if the key algorithm is not supported by the JCE or the key spec does not contain
     *             valid information
     */
    @Nonnull public static PublicKey getRSAKey(@Nonnull final RSAKeyValue keyDescriptor) throws KeyException {
        Constraint.isNotNull(keyDescriptor, "RSAKeyValue cannot be null");
        
        final Modulus mod = keyDescriptor.getModulus();
        final Exponent exp = keyDescriptor.getExponent();
        
        final RSAPublicKeySpec keySpec = new RSAPublicKeySpec(mod != null ? mod.getValueBigInt() : null,
                exp != null ? exp.getValueBigInt() : null);
        return buildKey(keySpec, JCAConstants.KEY_ALGO_RSA);
    }

    /**
     * Decode a base64-encoded ds:CryptoBinary value to a native Java BigInteger type.
     * 
     * @param base64Value base64-encoded CryptoBinary value
     * @return the decoded BigInteger
     * @throws DecodingException if the base64 value can not be decoded.
     */
    @Nonnull public static final BigInteger decodeBigIntegerFromCryptoBinary(@Nonnull final String base64Value) 
            throws DecodingException {
        try {
            return new BigInteger(1, Base64.getMimeDecoder().decode(base64Value));
        } catch (final IllegalArgumentException e) {
            throw new DecodingException("Unable to base64 decode data: " + e.getMessage(), e);
        }
    }

    /**
     * Encode a native Java BigInteger type to a base64-encoded ds:CryptoBinary value.
     * 
     * @param bigInt the BigInteger value
     * @return the encoded CryptoBinary value
     * @throws EncodingException if the BigInteger as bytes can not be base64 encoded.
     */
    @Nonnull @NotEmpty public static final String encodeCryptoBinaryFromBigInteger(@Nonnull final BigInteger bigInt) 
            throws EncodingException {
        Constraint.isNotNull(bigInt, "BigInteger cannot be null");
        
        // This code is really complicated, for now just use the Apache xmlsec lib code directly.
        final byte[] bigIntBytes = XMLUtils.getBytes(bigInt, bigInt.bitLength());
        return Base64.getEncoder().encodeToString(bigIntBytes);
    }

    /**
     * Generates a public key from the given key spec.
     * 
     * @param keySpec {@link KeySpec} specification for the key
     * @param keyAlgorithm key generation algorithm, only DSA and RSA supported
     * 
     * @return the generated {@link PublicKey}
     * 
     * @throws KeyException thrown if the key algorithm is not supported by the JCE or the key spec does not contain
     *             valid information
     */
    @Nonnull protected static PublicKey buildKey(@Nonnull final KeySpec keySpec, @Nonnull final String keyAlgorithm)
            throws KeyException {
        try {
            final KeyFactory keyFactory = KeyFactory.getInstance(keyAlgorithm);
            return keyFactory.generatePublic(keySpec);
        } catch (final NoSuchAlgorithmException e) {
            final String msg = keyAlgorithm + " algorithm is not supported by this JCE"; 
            LOG.error(msg + ": {}", e.getMessage());
            throw new KeyException(msg, e);
        } catch (final InvalidKeySpecException e) {
            LOG.error("Invalid key information: {}", e.getMessage());
            throw new KeyException("Invalid key information", e);
        }
    }

    /**
     * Extracts the public key within the {@link DEREncodedKeyValue}.
     * 
     * @param keyValue the {@link DEREncodedKeyValue} to extract the key from
     * 
     * @return a native Java security {@link java.security.Key} object
     * 
     * @throws KeyException thrown if the given key data can not be converted into {@link PublicKey}
     */
    @Nonnull public static PublicKey getKey(@Nonnull final DEREncodedKeyValue keyValue) throws KeyException{
        // Note: Testing shows DH must come before DSA.  If you attempt to decode a DH key as DSA,
        // it "works", b/c they have similar structures, but it's probably not correct.  DSA does not decode as DH,
        // so this ordering is what works at present.
        // This is now only relevant if the direct parsing of the key type below fails, and we fallback to
        // "try everything and pick the first that doesn't fail" approach.
        final String[] supportedKeyTypes = {
                JCAConstants.KEY_ALGO_RSA,
                JCAConstants.KEY_ALGO_EC,
                JCAConstants.KEY_ALGO_DIFFIE_HELLMAN,
                JCAConstants.KEY_ALGO_DSA};
        
        Constraint.isNotNull(keyValue, "DEREncodedKeyValue cannot be null");
        final String keyValueValue = keyValue.getValue();
        if (keyValueValue == null) {
            throw new KeyException("No data found in key value element");
        }
        byte[] encodedKey = null;
        try {
            encodedKey = Base64.getMimeDecoder().decode(keyValueValue);
        } catch (final IllegalArgumentException e) {
           throw new KeyException("DEREncodedKeyValue could not be base64 decoded",e);
        }

        final String parsedKeyType = parseKeyType(encodedKey);
        
        final String[] keyTypes = parsedKeyType != null ? new String[]{parsedKeyType}  : supportedKeyTypes;
        
        for (final String keyType : keyTypes) {
            LOG.trace("Attempting to decode DER key as type: {}", keyType);
            try {
                final KeyFactory keyFactory = KeyFactory.getInstance(keyType);
                final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
                final PublicKey publicKey = keyFactory.generatePublic(keySpec);
                if (publicKey != null) {
                    LOG.trace("DER key decoded successfully as type: {}", keyType);
                    return publicKey;
                }
            } catch (final NoSuchAlgorithmException | InvalidKeySpecException e) {
                LOG.trace("DER key failed decoding as: {}", keyType);
            }
        }
        throw new KeyException("DEREncodedKeyValue did not contain a supported key type");
    }

    /**
     * Parse the JCA key algorithm type from the ASN.1 encoded form of the public key.
     * 
     * <p>
     * Methodology is to parse the ASN.1 data to the <code>SubjectPublicKeyInfo</code>, read the
     * <code>AlgorithmIdentifier</code> for the key type's OID, then map the OID to the JCA
     * key algorithm.
     * </p>
     * 
     * @param encodedKey the ASN.1 encoded key
     * 
     * @return the JCA key algorithm, or null if the OID parsing or OID-to-algorithm mapping fails
     */
    private static String parseKeyType(@Nonnull final byte[] encodedKey) {
        try (final ASN1InputStream input = new ASN1InputStream(encodedKey)) {
            final SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(input.readObject());
            final String keyTypeOID = spki.getAlgorithm().getAlgorithm().getId();
            LOG.debug("Parsed key type OID: {}", keyTypeOID);
            
            String parsedKeyType = null;
            switch(keyTypeOID) {
                case "1.2.840.113549.1.1.1":
                    parsedKeyType = JCAConstants.KEY_ALGO_RSA;
                    break;
                case "1.2.840.10045.2.1":
                    parsedKeyType = JCAConstants.KEY_ALGO_EC;
                    break;
                case "1.2.840.10040.4.1":
                    parsedKeyType = JCAConstants.KEY_ALGO_DSA;
                    break;
                // There are apparently 2 OIDS in use for DH public keys.
                // This is what's defined in the specs for DH keys. See RFC 3279, section 2.3.3.
                case "1.2.840.10046.2.1":
                // This is what's defined in the specs for DH key agreement. See PKCS #3.
                // Which sounds wrong but: It's the one returned by Java KeyPairGenerator, etc
                case "1.2.840.113549.1.3.1":
                    parsedKeyType = JCAConstants.KEY_ALGO_DIFFIE_HELLMAN;
                    break;
                default:
                    parsedKeyType = null;
            }
            
            LOG.debug("Parsed key type: {}", parsedKeyType);
            return parsedKeyType;
        } catch (final Exception e) {
            LOG.warn("Error parsing encoded key, can not determine key type", e);
            return null;
        }
    }
    
    /**
     * Get the Java certificate factory singleton.
     * 
     * @return {@link CertificateFactory} the factory used to create X509 certificate objects
     * 
     * @throws CertificateException thrown if the factory can not be created
     */
    @Nonnull protected static CertificateFactory getX509CertFactory() throws CertificateException {

        if (x509CertFactory == null) {
            x509CertFactory = CertificateFactory.getInstance("X.509");
        }

        assert x509CertFactory != null;
        return x509CertFactory;
    }

    /**
     * Obtains a {@link KeyInfoGenerator} for the specified {@link Credential}.
     * 
     * <p>
     * The KeyInfoGenerator returned is resolved via the supplied {@link NamedKeyInfoGeneratorManager}
     * and is determined by the type of the signing credential and an optional KeyInfo generator profile configuration 
     * name. If the latter is ommited, the default manager ({@link NamedKeyInfoGeneratorManager#getDefaultManager()}) 
     * of the security configuration's named generator manager will be used.
     * </p>
     * 
     * @param credential the credential for which a generator is desired
     * @param manager the NamedKeyInfoGeneratorManager instance to use
     * @param keyInfoProfileName the named KeyInfoGeneratorManager configuration to use (may be null)
     * @return a KeyInfoGenerator appropriate for the specified credential
     */
    @Nullable public static KeyInfoGenerator getKeyInfoGenerator(@Nonnull final Credential credential,
            @Nonnull final NamedKeyInfoGeneratorManager manager, @Nullable final String keyInfoProfileName) {
        Constraint.isNotNull(credential, "Credential may not be null");
        Constraint.isNotNull(manager, "NamedKeyInfoGeneratorManager may not be null");
        
        KeyInfoGeneratorFactory factory = null;
        if (keyInfoProfileName != null) {
            LOG.trace("Resolving KeyInfoGeneratorFactory using profile name: {}", keyInfoProfileName);
            factory = manager.getFactory(keyInfoProfileName, credential);
        } else {
            LOG.trace("Resolving KeyInfoGeneratorFactory using default manager: {}", keyInfoProfileName);
            factory = manager.getDefaultManager().getFactory(credential);
        }
        
        if (factory != null) {
            LOG.trace("Found KeyInfoGeneratorFactory: {}", factory.getClass().getName());
            return factory.newInstance();
        }
        
        LOG.trace("Unable to resolve KeyInfoGeneratorFactory for credential");
        return null;
    }

}
