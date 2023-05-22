package com.github.lsjunior.icrypto.core.signature.cms;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.esf.CommitmentTypeIndication;
import org.bouncycastle.asn1.esf.CrlIdentifier;
import org.bouncycastle.asn1.esf.CrlValidatedID;
import org.bouncycastle.asn1.esf.ESFAttributes;
import org.bouncycastle.asn1.esf.OcspIdentifier;
import org.bouncycastle.asn1.esf.OcspResponsesID;
import org.bouncycastle.asn1.esf.OtherHash;
import org.bouncycastle.asn1.esf.OtherHashAlgAndValue;
import org.bouncycastle.asn1.esf.RevocationValues;
import org.bouncycastle.asn1.esf.SigPolicyQualifierInfo;
import org.bouncycastle.asn1.esf.SigPolicyQualifiers;
import org.bouncycastle.asn1.esf.SignaturePolicyId;
import org.bouncycastle.asn1.esf.SignaturePolicyIdentifier;
import org.bouncycastle.asn1.esf.SignerLocation;
import org.bouncycastle.asn1.ess.ContentHints;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.OtherCertID;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignatureAlgorithmNameGenerator;
import org.bouncycastle.cms.CMSSignatureEncryptionAlgorithmFinder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.DefaultCMSSignatureAlgorithmNameGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.SignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;

import com.github.lsjunior.icrypto.ICryptoException;
import com.github.lsjunior.icrypto.ICryptoLog;
import com.github.lsjunior.icrypto.api.model.CertificateId;
import com.github.lsjunior.icrypto.api.model.CertificateRevocationData;
import com.github.lsjunior.icrypto.api.model.Document;
import com.github.lsjunior.icrypto.api.model.ErrorMessage;
import com.github.lsjunior.icrypto.api.model.LocationName;
import com.github.lsjunior.icrypto.api.model.Signature;
import com.github.lsjunior.icrypto.api.model.SignatureId;
import com.github.lsjunior.icrypto.api.model.SignaturePolicy;
import com.github.lsjunior.icrypto.api.model.TimeStamp;
import com.github.lsjunior.icrypto.api.type.DigestType;
import com.github.lsjunior.icrypto.api.type.SignatureType;
import com.github.lsjunior.icrypto.core.certificate.CertPathProvider;
import com.github.lsjunior.icrypto.core.certificate.util.CertPaths;
import com.github.lsjunior.icrypto.core.certificate.util.Certificates;
import com.github.lsjunior.icrypto.core.crl.CrlProvider;
import com.github.lsjunior.icrypto.core.crl.impl.SimpleCrlProvider;
import com.github.lsjunior.icrypto.core.crl.util.Crls;
import com.github.lsjunior.icrypto.core.digest.Digester;
import com.github.lsjunior.icrypto.core.digest.util.Digesters;
import com.github.lsjunior.icrypto.core.ocsp.OcspProvider;
import com.github.lsjunior.icrypto.core.ocsp.impl.SimpleOcspProvider;
import com.github.lsjunior.icrypto.core.signature.cms.profile.BasicProfile;
import com.github.lsjunior.icrypto.core.timestamp.TimeStampProvider;
import com.github.lsjunior.icrypto.core.timestamp.util.TimeStamps;
import com.github.lsjunior.icrypto.core.util.Asn1Objects;
import com.github.lsjunior.icrypto.core.util.BcProvider;
import com.google.common.base.MoreObjects;
import com.google.common.collect.Iterables;
import com.google.common.hash.Hashing;
import com.google.common.io.BaseEncoding;
import com.google.common.io.ByteSource;
import com.google.common.io.Files;

public abstract class CadesServiceHelper {

  private static final String DEFAULT_CONTENT_TYPE = "application/octet-stream";

  private static final String CONTENT_HINT_PATTERN = "ContentType: %s\nContent-Disposition: attachment; filename=\"%s\"";

  private CadesServiceHelper() {
    //
  }

  public static SignerInfoGeneratorBuilder getSignerInfoGeneratorBuilder() throws OperatorCreationException {
    JcaDigestCalculatorProviderBuilder digestCalculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder();
    digestCalculatorProviderBuilder.setProvider(BcProvider.PROVIDER_NAME);
    DigestCalculatorProvider digestCalculatorProvider = digestCalculatorProviderBuilder.build();

    CMSSignatureEncryptionAlgorithmFinder encryptionAlgorithmFinder = RFC5754CMSSignatureEncryptionAlgorithmFinder.getInstance();

    SignerInfoGeneratorBuilder signerInfoGeneratorBuilder = new SignerInfoGeneratorBuilder(digestCalculatorProvider, encryptionAlgorithmFinder);
    return signerInfoGeneratorBuilder;
  }

  public static ASN1EncodableVector toAttributesVector(final Map<String, byte[]> map) {
    ASN1EncodableVector signedAttributesVector = new ASN1EncodableVector();
    for (Entry<String, byte[]> entry : map.entrySet()) {
      Attribute attribute = new Attribute(new ASN1ObjectIdentifier(entry.getKey()), ASN1Set.getInstance(entry.getValue()));
      signedAttributesVector.add(attribute);
    }

    return signedAttributesVector;
  }

  public static Collection<CRL> getCrls(final Certificate certificate, final CrlProvider crlProvider) throws GeneralSecurityException {
    return CadesServiceHelper.getCrls(Collections.singletonList(certificate), crlProvider);
  }

  public static Collection<CRL> getCrls(final List<Certificate> chain, final CrlProvider crlProvider) throws GeneralSecurityException {
    List<CRL> crls = new ArrayList<>();
    for (Certificate c : chain) {
      CRL crl = Crls.toCrl(crlProvider.getCrl(c));
      if (!crls.contains(crl)) {
        crls.add(crl);
      }
    }
    return crls;
  }

  public static String getSID(final SignerInfo signerInfo) throws IOException {
    if (signerInfo == null) {
      return null;
    }
    return BaseEncoding.base16().encode(signerInfo.getSID().getId().toASN1Primitive().getEncoded());
  }

  public static boolean isSignedData(final byte[] data) {
    try {
      CMSSignedData signedData = new CMSSignedData(data);
      ICryptoLog.getLogger().debug("Content is signed with version " + signedData.getVersion());
      return true;
    } catch (Exception e) {
      ICryptoLog.getLogger().debug(e.getMessage(), e);
      return false;
    }
  }

  public static ByteSource getContent(final ByteSource data) throws IOException, CMSException {
    ICryptoLog.getLogger().debug("getContent() HASH -> " + data.hash(Hashing.sha256()));
    CMSSignedData signedData = new CMSSignedData(data.openStream());
    CMSProcessable processable = signedData.getSignedContent();
    return CadesServiceHelper.getContent(processable);
  }

  public static ByteSource getContent(final InputStream inputStream) throws IOException, CMSException {
    CMSSignedData signedData = new CMSSignedData(inputStream);
    CMSProcessable processable = signedData.getSignedContent();
    return CadesServiceHelper.getContent(processable);
  }

  public static ByteSource getContent(final CMSProcessable processable) throws IOException {
    if (processable != null) {
      Object content = processable.getContent();
      if (content instanceof File) {
        File file = (File) content;
        return Files.asByteSource(file);
      }
      if (content instanceof InputStream) {
        InputStream inputStream = (InputStream) content;
        File tmpFile = File.createTempFile("cades-service-helper", ".tmp");
        Files.asByteSink(tmpFile).writeFrom(inputStream);
        return Files.asByteSource(tmpFile);
      }
      byte[] bytes = (byte[]) content;
      if (bytes.length > 0) {
        return ByteSource.wrap(bytes);
      }
      return null;
    }
    return null;
  }

  public static DERUTF8String getContentHint(final String contentName, final String contentType) {
    String str = String.format(CadesServiceHelper.CONTENT_HINT_PATTERN, MoreObjects.firstNonNull(contentType, CadesServiceHelper.DEFAULT_CONTENT_TYPE), contentName);
    DERUTF8String hint = new DERUTF8String(str);
    return hint;
  }

  public static SignerId toSignerId(final Certificate certificate) {
    X509Certificate cx = (X509Certificate) certificate;
    X500Name issuer = Certificates.toX500Name(cx.getIssuerX500Principal());
    BigInteger serialNumber = cx.getSerialNumber();
    byte[] subjectKeyId = cx.getExtensionValue(Extension.subjectKeyIdentifier.getId());

    return new SignerId(issuer, serialNumber, subjectKeyId);
  }

  public static OtherCertID toOtherCertID(final Certificate certificate, final Certificate issuer, final DigestType digestType) throws CertificateEncodingException, IOException {
    AlgorithmIdentifier digestAlgorithmIdentifier = Asn1Objects.getAlgorithmIdentifier(digestType);
    byte[] certificateHash = Digesters.getDigester(digestType).digest(certificate.getEncoded());
    IssuerSerial issuerSerial = null;
    if (issuer != null) {
      X509CertificateHolder certificateHolder = Certificates.toCertificateHolder(certificate);
      X509CertificateHolder issuerHolder = Certificates.toCertificateHolder(issuer);
      issuerSerial = new IssuerSerial(issuerHolder.getSubject(), certificateHolder.getSerialNumber());
    }

    OtherCertID othercertid = new OtherCertID(digestAlgorithmIdentifier, certificateHash, issuerSerial);
    return othercertid;
  }

  public static CrlValidatedID toCrlValidatedID(final CRL crl, final DigestType digestType) throws CRLException, IOException {
    X509CRL x509crl = (X509CRL) crl;
    Digester digester = Digesters.getDigester(digestType);
    byte[] digest = digester.digest(x509crl.getEncoded());
    OtherHash hash = null;
    if (digestType != DigestType.SHA1) {
      OtherHashAlgAndValue hashAlgAndValue = new OtherHashAlgAndValue(Asn1Objects.getAlgorithmIdentifier(digestType), new DEROctetString(digest));
      hash = new OtherHash(hashAlgAndValue);
    } else {
      hash = new OtherHash(digest);
    }
    CrlIdentifier id = null;
    byte[] crlNumberBytes = x509crl.getExtensionValue(Extension.cRLNumber.getId());
    if (crlNumberBytes != null) {
      ASN1Primitive primitive = ASN1Primitive.fromByteArray(crlNumberBytes);
      BigInteger bi = null;
      if (primitive instanceof ASN1Integer) {
        bi = ((ASN1Integer) primitive).getPositiveValue();
      } else if (primitive instanceof ASN1String) {
        bi = new BigInteger(((ASN1String) primitive).getString());
      }
      id = new CrlIdentifier(new X500Name(x509crl.getIssuerX500Principal().getName()), new ASN1UTCTime(x509crl.getThisUpdate()), bi);
    } else {
      id = new CrlIdentifier(new X500Name(x509crl.getIssuerX500Principal().getName()), new ASN1UTCTime(x509crl.getThisUpdate()));
    }

    CrlValidatedID cvid = new CrlValidatedID(hash, id);
    return cvid;
  }

  public static OcspResponsesID toOcspResponsesID(final OCSPResp resp, final DigestType digestType) throws OCSPException, IOException {
    if (resp != null) {
      Object obj = resp.getResponseObject();
      if (obj instanceof BasicOCSPResp) {
        BasicOCSPResp bResp = (BasicOCSPResp) resp.getResponseObject();
        return CadesServiceHelper.toOcspResponsesID(bResp, digestType);
      }
    }
    return null;
  }

  public static OcspResponsesID toOcspResponsesID(final BasicOCSPResp resp, final DigestType digestType) throws IOException {
    byte[] encoded = resp.getEncoded();
    Digester digester = Digesters.getDigester(digestType);
    byte[] digest = digester.digest(encoded);
    AlgorithmIdentifier algorithmIdentifier = Asn1Objects.getAlgorithmIdentifier(digestType);
    OtherHashAlgAndValue otherHashAlgAndValue = new OtherHashAlgAndValue(algorithmIdentifier, new DEROctetString(digest));
    OtherHash hash = new OtherHash(otherHashAlgAndValue);
    OcspIdentifier oid = new OcspIdentifier(resp.getResponderId().toASN1Primitive(), new ASN1GeneralizedTime(resp.getProducedAt()));
    OcspResponsesID ocrid = new OcspResponsesID(oid, hash);
    return ocrid;
  }

  public static ESSCertIDv2 getESSCertIDv2(final Certificate certificate, final Certificate issuer, final DigestType digestType) throws CertificateEncodingException, IOException {
    AlgorithmIdentifier digestAlgorithmIdentifier = null;
    byte[] certificateHash = Digesters.getDigester(digestType).digest(certificate.getEncoded());
    IssuerSerial issuerSerial = null;
    if (issuer != null) {
      X509CertificateHolder certificateHolder = Certificates.toCertificateHolder(certificate);
      X509CertificateHolder issuerHolder = Certificates.toCertificateHolder(issuer);
      issuerSerial = new IssuerSerial(issuerHolder.getSubject(), certificateHolder.getSerialNumber());
    }

    if (digestType != DigestType.SHA256) {
      digestAlgorithmIdentifier = Asn1Objects.getAlgorithmIdentifier(digestType);
    }

    ESSCertIDv2 essCertIdV2 = new ESSCertIDv2(digestAlgorithmIdentifier, certificateHash, issuerSerial);

    return essCertIdV2;
  }

  public static ESSCertID getESSCertID(final Certificate certificate, final Certificate issuer) throws CertificateEncodingException, IOException {
    byte[] certificateHash = Digesters.SHA1.digest(certificate.getEncoded());
    IssuerSerial issuerSerial = null;
    if (issuer != null) {
      X509CertificateHolder certificateHolder = Certificates.toCertificateHolder(certificate);
      X509CertificateHolder issuerHolder = Certificates.toCertificateHolder(issuer);
      issuerSerial = new IssuerSerial(issuerHolder.getSubject(), certificateHolder.getSerialNumber());
    }

    ESSCertID essCertId = new ESSCertID(certificateHash, issuerSerial);
    return essCertId;
  }

  public static Map<Certificate, CertificateRevocationData> getCrlAndOcsps(final List<Certificate> chain, final CrlProvider crlProvider, final OcspProvider ocspProvider) throws IOException, OCSPException, GeneralSecurityException {
    Map<Certificate, CertificateRevocationData> revocations = new HashMap<>();
    for (int i = 0; i < chain.size(); i++) {
      Certificate certificate = chain.get(i);
      X509Certificate x509Certificate = (X509Certificate) certificate;
      X509Certificate x509Issuer = null;
      if ((i + 1) < chain.size()) {
        x509Issuer = (X509Certificate) chain.get(i + 1);
      } else {
        x509Issuer = x509Certificate;
      }

      byte[] crlBytes = crlProvider.getCrl(certificate);
      byte[] ocspBytes = ocspProvider.getOcsp(x509Certificate, x509Issuer);

      if ((crlBytes != null) || (ocspBytes != null)) {
        CertificateRevocationData revocationData = new CertificateRevocationData();

        if (crlBytes != null) {
          revocationData.setCrl(Crls.toCrl(crlBytes));
        }

        if (ocspBytes != null) {
          OCSPResp ocspResp = new OCSPResp(ocspBytes);
          BasicOCSPResp basicOcspResp = (BasicOCSPResp) ocspResp.getResponseObject();
          revocationData.setOcsp(basicOcspResp.getEncoded());
        }

        revocations.put(certificate, revocationData);
      }
    }

    return revocations;
  }

  public static SignerInformation getSignerInformation(final SignerInformationStore signerInformationStore, final Certificate certificate, final int index) {
    if (certificate != null) {
      return CadesServiceHelper.getSignerInformation(signerInformationStore, certificate);
    }
    return CadesServiceHelper.getSignerInformation(signerInformationStore, index);
  }

  public static SignerInformation getSignerInformation(final SignerInformationStore signerInformationStore, final int index) {
    Collection<SignerInformation> collection = signerInformationStore.getSigners();
    if ((collection != null) && (collection.size() >= index)) {
      return Iterables.get(collection, index);
    }
    return null;
  }

  public static SignerInformation getSignerInformation(final SignerInformationStore signerInformationStore, final Certificate certificate) {
    return signerInformationStore.get(CadesServiceHelper.toSignerId(certificate));
  }

  public static CadesSignatureContext getContext(final CadesSignatureParameters parameters) throws CertPathBuilderException, IOException {
    String contentName = parameters.getContentName();
    TimeStamp contentTimeStamp = parameters.getContentTimeStamp();
    String contentType = parameters.getContentType();
    ByteSource data = parameters.getData();
    Date date = parameters.getDate();
    boolean dataDigested = parameters.isDataDigested();
    boolean detached = parameters.isDetached();
    boolean validateCertificate = parameters.isValidateCertificate();
    boolean ignoreSigningTime = parameters.isIgnoreSigningTime();
    String digestProvider = parameters.getDigestProvider();
    CertPathProvider certPathProvider = parameters.getCertPathProvider();
    SignatureProfile signatureProfile = parameters.getSignatureProfile();
    String commitmentType = parameters.getCommitmentType();
    CrlProvider crlProvider = parameters.getCrlProvider();
    OcspProvider ocspProvider = parameters.getOcspProvider();
    LocationName locationName = parameters.getLocation();
    String provider = parameters.getProvider();
    Map<Certificate, CertificateRevocationData> revocations = parameters.getRevocations();
    SignatureId signatureId = parameters.getSignatureId();
    SignaturePolicy signaturePolicy = parameters.getSignaturePolicy();
    SignatureType signatureType = SignatureType.get(parameters.getAlgorithm());
    String signatureProvider = parameters.getSignatureProvider();
    TimeStampProvider timeStampClient = parameters.getTimeStampProvider();

    if (crlProvider == null) {
      crlProvider = new SimpleCrlProvider();
    }
    if (ocspProvider == null) {
      ocspProvider = new SimpleOcspProvider();
    }
    if (signatureProfile == null) {
      signatureProfile = new BasicProfile();
    }

    if (provider == null) {
      provider = BcProvider.PROVIDER_NAME;
    }

    File file = File.createTempFile("cades-signature", ".dat");
    File signedFile = File.createTempFile("cades-signature", ".p7s");
    data.copyTo(Files.asByteSink(file));

    CadesSignatureContext context = new CadesSignatureContext();
    context.setCertPathProvider(certPathProvider);
    context.setCommitmentType(commitmentType);
    context.setContentName(contentName);
    context.setContentTimeStamp(contentTimeStamp);
    context.setContentType(contentType);
    context.setCrlProvider(crlProvider);
    context.setData(file);
    context.setDate(date);
    context.setDataDigested(dataDigested);
    context.setDetached(detached);
    context.setDigestProvider(MoreObjects.firstNonNull(digestProvider, provider));
    context.setIgnoreSigningTime(ignoreSigningTime);
    context.setLocationName(locationName);
    context.setOcspProvider(ocspProvider);
    context.setPolicy(signaturePolicy);
    context.setProfile(signatureProfile);
    context.setRevocations(revocations);
    context.setSignedData(signedFile);
    context.setSignatureId(signatureId);
    context.setSignatureProvider(MoreObjects.firstNonNull(signatureProvider, provider));
    context.setSignatureType(signatureType);
    context.setTimeStampClient(timeStampClient);
    context.setValidateCertificate(Boolean.valueOf(validateCertificate));

    if (parameters.getSignedAttributes() != null) {
      context.setSignedAttributes(parameters.getSignedAttributes());
    } else {
      context.setSignedAttributes(new HashMap<String, byte[]>());
    }

    if (parameters.getUnsignedAttributes() != null) {
      context.setUnsignedAttributes(parameters.getUnsignedAttributes());
    } else {
      context.setUnsignedAttributes(new HashMap<String, byte[]>());
    }

    if (parameters.getIdentity() != null) {
      context.setPrivateKey(parameters.getIdentity().getPrivateKey());

      List<Certificate> chain = parameters.getIdentity().getChain();
      if ((chain.size() == 1) && (certPathProvider != null)) {
        CertPath certPath = certPathProvider.getCertPath(chain.get(0));
        List<Certificate> tmpChain = CertPaths.toCertificate(certPath);
        if (tmpChain != null) {
          chain = tmpChain;
        }
      }

      context.setChain(chain);
    }

    return context;
  }

  public static ContentSigner getContentSigner(final PrivateKey privateKey, final String algorithm, final String provider) throws OperatorCreationException {
    JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder(algorithm);
    contentSignerBuilder.setProvider(provider);
    ContentSigner contentSigner = contentSignerBuilder.build(privateKey);
    return contentSigner;
  }

  public static CMSAttributeTableGenerator getCmsAttributeTableGenerator(final AttributeTable table, boolean ignoreSigningTime) {
    if (ignoreSigningTime) {
      return new DefaultSignedAttributeTableGenerator() {

        @Override
        @SuppressWarnings("rawtypes")
        protected Hashtable createStandardAttributeTable(Map parameters) {
          Hashtable ht = super.createStandardAttributeTable(parameters);
          if (ignoreSigningTime) {
            ht.remove(CMSAttributes.signingTime);
          }
          return ht;
        }

      };
    }
    return new DefaultSignedAttributeTableGenerator(table);
  }

  public static Document toDocument(final CMSSignedData cmsSignedData, final CertPathProvider certPathProvider, final SignaturePolicyProvider signaturePolicyProvider, final List<Certificate> chain)
      throws CMSException, TSPException, IOException, GeneralSecurityException, ParseException, OperatorCreationException {
    Collection<X509CertificateHolder> certificates = cmsSignedData.getCertificates().getMatches(null);
    Collection<X509CRLHolder> crls = cmsSignedData.getCRLs().getMatches(null);

    Document document = new Document();
    List<ErrorMessage> errors = new ArrayList<>();
    document.setErrors(errors);

    document.setCertificates(Certificates.toCertificates(certificates));
    document.setCrls(Crls.toCrls(crls));
    document.setContent(CadesServiceHelper.getContent(cmsSignedData.getSignedContent()));
    document.setSignatures(CadesServiceHelper.getSignatures(cmsSignedData, certPathProvider, signaturePolicyProvider, chain));

    return document;
  }

  @SuppressWarnings({"unchecked", "rawtypes"})
  public static List<Signature> getSignatures(final CMSSignedData signedData, final CertPathProvider certPathProvider, final SignaturePolicyProvider signaturePolicyProvider, final List<Certificate> chain)
      throws CMSException, TSPException, IOException, GeneralSecurityException, ParseException, OperatorCreationException {
    Store certificatesStore = signedData.getCertificates();
    SignerInformationStore signerInformationStore = signedData.getSignerInfos();
    Collection<SignerInformation> informations = signerInformationStore.getSigners();
    List<Signature> signatures = new ArrayList<>();

    if (informations != null) {
      for (SignerInformation information : informations) {
        Signature signature = new Signature();
        List<ErrorMessage> errors = new ArrayList<>();
        signature.setErrors(errors);
        signature.setEncoded(ByteSource.wrap(information.toASN1Structure().getEncoded()));
        signature.setSignature(ByteSource.wrap(information.getSignature()));

        AttributeTable signedAttributeTable = information.getSignedAttributes();
        AttributeTable unsignedAttributeTable = information.getUnsignedAttributes();

        signature.setSignedAttributes(CadesServiceHelper.toMap(signedAttributeTable));
        signature.setUnsignedAttributes(CadesServiceHelper.toMap(unsignedAttributeTable));

        CertificateId signingCertificate = CadesServiceHelper.getSigningCertificate(signedAttributeTable);
        signature.setCertificateId(signingCertificate);

        TimeStamp contentTimeStamp = CadesServiceHelper.getContentTimeStamp(signedAttributeTable);
        signature.setContentTimeStamp(contentTimeStamp);

        TimeStamp signatureTimeStamp = CadesServiceHelper.getSignatureTimeStamp(unsignedAttributeTable);
        signature.setSignatureTimeStamp(signatureTimeStamp);

        TimeStamp referenceTimeStamp = CadesServiceHelper.getReferenceTimeStamp(unsignedAttributeTable);
        signature.setReferenceTimeStamp(referenceTimeStamp);

        TimeStamp archiveTimeStamp = CadesServiceHelper.getArchiveTimeStamp(unsignedAttributeTable);
        signature.setArchiveTimeStamp(archiveTimeStamp);

        Date signingTime = CadesServiceHelper.getSigningTime(signedAttributeTable);
        signature.setSigningTime(signingTime);

        SignaturePolicy signaturePolicy = CadesServiceHelper.getSignaturePolicy(signaturePolicyProvider, signedAttributeTable);
        if (signaturePolicy != null) {
          signature.setSignaturePolicy(signaturePolicy);
        } else {
          ErrorMessage error = new ErrorMessage(CadesErrors.POLICY_NOT_FOUND, "Policy ID signed attribute not found", false);
          signature.getErrors().add(error);
        }

        String commitmentType = CadesServiceHelper.getCommitmentType(signedAttributeTable);
        signature.setCommitmentType(commitmentType);

        LocationName signerLocation = CadesServiceHelper.getSignerLocation(signedAttributeTable);
        signature.setSignerLocation(signerLocation);

        String contentType = CadesServiceHelper.getContentType(signedAttributeTable);
        signature.setContentType(contentType);

        byte[] messageDigest = CadesServiceHelper.getMessageDigest(signedAttributeTable);
        signature.setMessageDigest(BaseEncoding.base16().encode(messageDigest));

        String contentHints = CadesServiceHelper.getContentHints(signedAttributeTable);
        signature.setContentHints(contentHints);

        SignatureType signatureType = Asn1Objects.getSignatureType(information.getDigestAlgOID(), information.getEncryptionAlgOID());
        signature.setSignatureType(signatureType);

        SignerId signerId = information.getSID();
        Collection<X509CertificateHolder> certificateMatches = certificatesStore.getMatches(signerId);
        X509CertificateHolder certificateHolder = null;

        if ((certificateMatches != null) && (!certificateMatches.isEmpty())) {
          certificateHolder = certificateMatches.iterator().next();
        } else if ((chain != null) && (!chain.isEmpty())) {
          certificateHolder = Certificates.toCertificateHolder(chain.get(0));
        }

        if (certificateHolder != null) {
          boolean valid = CadesServiceHelper.isValid(information, certificateHolder);
          if (!valid) {
            ErrorMessage error = new ErrorMessage(CadesErrors.SIGNATURE_INVALID, "Invalid signature", true);
            signature.getErrors().add(error);
          }

          List<Certificate> newChain = null;
          if (certPathProvider != null) {
            Certificate certificate = Certificates.toCertificate(certificateHolder);
            try {
              CertPath certPath = certPathProvider.getCertPath(certificate);
              newChain = CertPaths.toCertificate(certPath);
            } catch (CertPathBuilderException e) {
              ICryptoLog.getLogger().debug(e.getMessage(), e);
              signature.getErrors().add(new ErrorMessage(CadesErrors.CERTIFICATE_HIERARCHY_INVALID, "Invalid certificate hierarchy", false));
              newChain = Collections.singletonList(Certificates.toCertificate(certificateHolder));
            }
          } else if (chain != null) {
            newChain = chain;
          } else {
            Collection<X509CertificateHolder> allMatches = certificatesStore.getMatches(null);
            if ((allMatches != null) && (allMatches.size() >= 2)) {
              newChain = Certificates.getChain(certificateHolder, allMatches);
            } else {
              newChain = Collections.singletonList(Certificates.toCertificate(certificateHolder));
            }
          }
          signature.setChain(newChain);
        } else {
          signature.getErrors().add(new ErrorMessage(CadesErrors.CERTIFICATE_NOT_FOUND, "Signer certificate not found", false));
        }

        signatures.add(signature);
      }
    }

    return signatures;
  }

  public static boolean isValid(final SignerInformation signerInformation, final X509CertificateHolder certificateHolder) throws OperatorCreationException, CertificateException {
    JcaContentVerifierProviderBuilder jcaContentVerifierProviderBuilder = new JcaContentVerifierProviderBuilder();
    jcaContentVerifierProviderBuilder.setProvider(BcProvider.PROVIDER_NAME);

    ContentVerifierProvider contentVerifierProvider = jcaContentVerifierProviderBuilder.build(certificateHolder);

    JcaDigestCalculatorProviderBuilder digestCalculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder();
    digestCalculatorProviderBuilder.setProvider(BcProvider.PROVIDER_NAME);
    DigestCalculatorProvider digestCalculatorProvider = digestCalculatorProviderBuilder.build();

    SignatureAlgorithmIdentifierFinder signatureAlgorithmIdentifierFinder = new DefaultSignatureAlgorithmIdentifierFinder();
    CMSSignatureAlgorithmNameGenerator signatureAlgorithmNameGenerator = new DefaultCMSSignatureAlgorithmNameGenerator();

    try {
      SignerInformationVerifier signerInformationVerifier = new SignerInformationVerifier(signatureAlgorithmNameGenerator, signatureAlgorithmIdentifierFinder, contentVerifierProvider, digestCalculatorProvider);
      return signerInformation.verify(signerInformationVerifier);
    } catch (CMSException e) {
      ICryptoLog.getLogger().debug(e.getMessage(), e);
      return false;
    }
  }

  public static boolean isValidAttribute(final byte[] bytes) {
    if (bytes == null) {
      return false;
    }
    Attribute attribute = Attribute.getInstance(bytes);
    return CadesServiceHelper.isValidAttribute(attribute);
  }

  public static boolean isValidAttribute(final Attribute attribute) {
    if (attribute == null) {
      return false;
    }
    ASN1Set asn1Set = attribute.getAttrValues();
    if (asn1Set.size() == 0) {
      return false;
    }
    return true;
  }

  @SuppressWarnings("unchecked")
  public static Map<String, byte[]> toMap(final AttributeTable attributeTable) throws IOException {
    if (attributeTable == null) {
      return Collections.emptyMap();
    }
    Map<String, byte[]> map = new HashMap<>();
    for (Object obj : attributeTable.toHashtable().entrySet()) {
      Entry<ASN1ObjectIdentifier, Attribute> entry = (Entry<ASN1ObjectIdentifier, Attribute>) obj;
      map.put(entry.getKey().getId(), entry.getValue().getEncoded());
    }
    return map;
  }

  public static String getContentType(final AttributeTable attributeTable) {
    ASN1Set contentTypeSet = CadesServiceHelper.getAttributeValue(PKCSObjectIdentifiers.pkcs_9_at_contentType, attributeTable);
    if (contentTypeSet != null) {
      ASN1Encodable encodable = contentTypeSet.getObjectAt(0);
      ASN1ObjectIdentifier asn1ObjectIdentifier = ASN1ObjectIdentifier.getInstance(encodable);
      return asn1ObjectIdentifier.getId();
    }
    return null;
  }

  public static byte[] getMessageDigest(final AttributeTable attributeTable) {
    ASN1Set contentTypeSet = CadesServiceHelper.getAttributeValue(CMSAttributes.messageDigest, attributeTable);
    if (contentTypeSet != null) {
      ASN1Encodable encodable = contentTypeSet.getObjectAt(0);
      ASN1OctetString asn1OctetString = ASN1OctetString.getInstance(encodable);
      return asn1OctetString.getOctets();
    }
    return null;
  }

  public static CertificateId getSigningCertificate(final AttributeTable attributeTable) {
    X500Name x500Name = null;
    ASN1Integer serial = null;
    byte[] hash = null;
    AlgorithmIdentifier algorithmIdentifier = null;
    boolean create = false;

    ASN1Set signingCertificateV2Set = CadesServiceHelper.getAttributeValue(PKCSObjectIdentifiers.id_aa_signingCertificateV2, attributeTable);
    ASN1Set signingCertificateSet = CadesServiceHelper.getAttributeValue(PKCSObjectIdentifiers.id_aa_signingCertificate, attributeTable);

    if (signingCertificateV2Set != null) {
      ASN1Encodable encodable = signingCertificateV2Set.getObjectAt(0);
      SigningCertificateV2 signingCertificateV2 = SigningCertificateV2.getInstance(encodable);
      ESSCertIDv2[] certIDv2s = signingCertificateV2.getCerts();
      ESSCertIDv2 certIDv2 = certIDv2s[0];
      IssuerSerial issuerSerial = certIDv2.getIssuerSerial();

      algorithmIdentifier = certIDv2.getHashAlgorithm();
      hash = certIDv2.getCertHash();
      create = true;

      if (algorithmIdentifier == null) {
        algorithmIdentifier = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
      }

      if (issuerSerial != null) {
        GeneralNames generalNames = issuerSerial.getIssuer();
        x500Name = Certificates.toX500Name(generalNames);
        serial = issuerSerial.getSerial();
      }
    } else if (signingCertificateSet != null) {
      ASN1Encodable encodable = signingCertificateSet.getObjectAt(0);
      SigningCertificate signingCertificate = SigningCertificate.getInstance(encodable);
      ESSCertID[] certIDs = signingCertificate.getCerts();
      ESSCertID certID = certIDs[0];
      IssuerSerial issuerSerial = certID.getIssuerSerial();

      algorithmIdentifier = new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1);
      hash = certID.getCertHash();
      create = true;

      if (issuerSerial != null) {
        GeneralNames generalNames = issuerSerial.getIssuer();
        x500Name = Certificates.toX500Name(generalNames);
        serial = issuerSerial.getSerial();
      }
    }

    if (create) {
      CertificateId certificateId = new CertificateId();
      certificateId.setDigest(hash);
      certificateId.setDigestType(Asn1Objects.getDigestType(algorithmIdentifier));

      if (x500Name != null) {
        certificateId.setIssuer(Certificates.toString(x500Name));
      }

      if (serial != null) {
        certificateId.setSerial(serial.getValue());
      }

      return certificateId;
    }

    return null;
  }

  public static TimeStamp getContentTimeStamp(final AttributeTable attributeTable) throws TSPException, IOException, CMSException, GeneralSecurityException {
    ASN1Set timeStampSet = CadesServiceHelper.getAttributeValue(PKCSObjectIdentifiers.id_aa_ets_contentTimestamp, attributeTable);
    if (timeStampSet != null) {
      ASN1Encodable encodable = timeStampSet.getObjectAt(0);
      return TimeStamps.toTimeStamp(encodable.toASN1Primitive().getEncoded());
    }
    return null;
  }

  public static TimeStamp getSignatureTimeStamp(final AttributeTable attributeTable) throws TSPException, IOException, CMSException, GeneralSecurityException {
    ASN1Set timeStampSet = CadesServiceHelper.getAttributeValue(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken, attributeTable);
    if (timeStampSet != null) {
      ASN1Encodable encodable = timeStampSet.getObjectAt(0);
      return TimeStamps.toTimeStamp(encodable.toASN1Primitive().getEncoded());
    }
    return null;
  }

  public static TimeStamp getReferenceTimeStamp(final AttributeTable attributeTable) throws TSPException, IOException, CMSException, GeneralSecurityException {
    ASN1Set timeStampSet = CadesServiceHelper.getAttributeValue(PKCSObjectIdentifiers.id_aa_ets_escTimeStamp, attributeTable);
    if (timeStampSet != null) {
      ASN1Encodable encodable = timeStampSet.getObjectAt(0);
      return TimeStamps.toTimeStamp(encodable.toASN1Primitive().getEncoded());
    }
    return null;
  }

  public static TimeStamp getArchiveTimeStamp(final AttributeTable attributeTable) throws TSPException, IOException, CMSException, GeneralSecurityException {
    ASN1Set timeStampSet = CadesServiceHelper.getAttributeValue(ESFAttributes.archiveTimestampV2, attributeTable);
    if (timeStampSet != null) {
      ASN1Encodable encodable = timeStampSet.getObjectAt(0);
      return TimeStamps.toTimeStamp(encodable.toASN1Primitive().getEncoded());
    }
    return null;
  }

  public static Date getSigningTime(final AttributeTable attributeTable) throws ParseException {
    ASN1Set signTimeSet = CadesServiceHelper.getAttributeValue(PKCSObjectIdentifiers.pkcs_9_at_signingTime, attributeTable);
    if (signTimeSet != null) {
      ASN1Encodable encodable = signTimeSet.getObjectAt(0);
      ASN1UTCTime time = ASN1UTCTime.getInstance(encodable);
      return time.getAdjustedDate();
    }
    return null;
  }

  public static SignaturePolicy getSignaturePolicy(final SignaturePolicyProvider signaturePolicyProvider, final AttributeTable attributeTable) {
    ASN1Set policyIdSet = CadesServiceHelper.getAttributeValue(PKCSObjectIdentifiers.id_aa_ets_sigPolicyId, attributeTable);
    if (policyIdSet != null) {
      ASN1Encodable asn1Encodable = policyIdSet.getObjectAt(0);
      SignaturePolicyIdentifier signaturePolicyIdentifier = SignaturePolicyIdentifier.getInstance(asn1Encodable);
      SignaturePolicyId signaturePolicyId = signaturePolicyIdentifier.getSignaturePolicyId();
      OtherHashAlgAndValue otherHashAlgAndValue = signaturePolicyId.getSigPolicyHash();

      SignaturePolicy signaturePolicy = new SignaturePolicy();

      signaturePolicy.setPolicyId(signaturePolicyId.getSigPolicyId().getId());
      signaturePolicy.setDigestValue(otherHashAlgAndValue.getHashValue().getOctets());
      signaturePolicy.setDigestType(Asn1Objects.getDigestType(otherHashAlgAndValue.getHashAlgorithm()));

      SigPolicyQualifiers policyQualifiers = signaturePolicyId.getSigPolicyQualifiers();
      if (policyQualifiers != null) {
        for (int i = 0; i < policyQualifiers.size(); i++) {
          SigPolicyQualifierInfo policyQualifierInfo = policyQualifiers.getInfoAt(i);
          if (policyQualifierInfo.getSigPolicyQualifierId().getId().equals(PKCSObjectIdentifiers.id_spq_ets_uri.getId())) {
            ASN1Encodable sigQualifier = policyQualifierInfo.getSigQualifier();
            if (sigQualifier instanceof ASN1String) {
              ASN1String sigQualifierString = (ASN1String) sigQualifier;
              signaturePolicy.setPolicyUrl(sigQualifierString.getString());
            }
            if (sigQualifier instanceof ASN1TaggedObject) {
              ASN1TaggedObject sigQualifierTaggedObject = (ASN1TaggedObject) sigQualifier;
              signaturePolicy.setPolicyUrl(Asn1Objects.toString(sigQualifierTaggedObject));
            } else {
              ASN1IA5String deria5String = ASN1IA5String.getInstance(policyQualifierInfo.getSigQualifier());
              signaturePolicy.setPolicyUrl(deria5String.getString());
            }
          }
        }
      }

      if ((signaturePolicy != null) && (signaturePolicyProvider != null)) {
        SignaturePolicy tmp = signaturePolicyProvider.getPolicy(signaturePolicy.getPolicyId());
        if (tmp != null) {
          signaturePolicy = tmp;
        }
      }

      return signaturePolicy;
    }
    return null;
  }

  public static String getCommitmentType(final AttributeTable attributeTable) {
    ASN1Set signTimeSet = CadesServiceHelper.getAttributeValue(PKCSObjectIdentifiers.id_aa_ets_commitmentType, attributeTable);
    if (signTimeSet != null) {
      ASN1Encodable encodable = signTimeSet.getObjectAt(0);
      CommitmentTypeIndication commitmentTypeIndication = CommitmentTypeIndication.getInstance(encodable);
      return commitmentTypeIndication.getCommitmentTypeId().getId();
    }
    return null;
  }

  public static LocationName getSignerLocation(final AttributeTable attributeTable) {
    ASN1Set signerLocationSet = CadesServiceHelper.getAttributeValue(PKCSObjectIdentifiers.id_aa_ets_signerLocation, attributeTable);
    if (signerLocationSet != null) {
      ASN1Encodable encodable = signerLocationSet.getObjectAt(0);
      SignerLocation signerLocation = SignerLocation.getInstance(encodable);
      LocationName locationName = new LocationName(signerLocation.getCountry().getString(), signerLocation.getLocality().getString());
      return locationName;
    }
    return null;
  }

  public static String getContentHints(final AttributeTable attributeTable) {
    ASN1Set contentHintSet = CadesServiceHelper.getAttributeValue(CMSAttributes.contentHint, attributeTable);
    if (contentHintSet != null) {
      ASN1Encodable encodable = contentHintSet.getObjectAt(0);
      ContentHints contentHints = ContentHints.getInstance(encodable);
      return contentHints.getContentDescriptionUTF8().getString();
    }
    return null;
  }

  public static byte[] wrap(final byte[] signature, final byte[] data) throws IOException {
    ContentInfo signatureContentInfo = ContentInfo.getInstance(signature);
    SignedData signatureSignedData = SignedData.getInstance(signatureContentInfo.getContent());
    ContentInfo dataContentInfo = new ContentInfo(CMSObjectIdentifiers.data, new BEROctetString(data));
    SignedData dataSignedData = new SignedData(signatureSignedData.getDigestAlgorithms(), dataContentInfo, signatureSignedData.getCertificates(), signatureSignedData.getCRLs(), signatureSignedData.getSignerInfos());
    ContentInfo fullContentInfo = new ContentInfo(PKCSObjectIdentifiers.signedData, dataSignedData);
    return fullContentInfo.getEncoded();
  }

  public static ByteSource merge(final List<ByteSource> signatures) {
    try {
      ByteSource data = signatures.get(0);
      CMSSignedData signedData = new CMSSignedData(data.openStream());
      Collection<SignerInformation> informations = new ArrayList<>();
      Collection<X509CertificateHolder> certificates = new ArrayList<>();
      Collection<X509CRLHolder> crls = new ArrayList<>();
      Collection<X509AttributeCertificateHolder> attributes = new ArrayList<>();

      informations.addAll(signedData.getSignerInfos().getSigners());
      certificates.addAll(signedData.getCertificates().getMatches(null));
      crls.addAll(signedData.getCRLs().getMatches(null));
      attributes.addAll(signedData.getAttributeCertificates().getMatches(null));

      for (int i = 1; i < signatures.size(); i++) {
        ByteSource tmpData = signatures.get(i);
        CMSSignedData tmpSignedData = new CMSSignedData(tmpData.openStream());

        informations.addAll(tmpSignedData.getSignerInfos().getSigners());
        certificates.addAll(tmpSignedData.getCertificates().getMatches(null));
        crls.addAll(tmpSignedData.getCRLs().getMatches(null));
        attributes.addAll(tmpSignedData.getAttributeCertificates().getMatches(null));
      }

      CollectionStore<X509CertificateHolder> certStore = new CollectionStore<>(certificates);
      CollectionStore<X509AttributeCertificateHolder> attrStore = new CollectionStore<>(attributes);
      CollectionStore<X509CRLHolder> crlStore = new CollectionStore<>(crls);

      signedData = CMSSignedData.replaceCertificatesAndCRLs(signedData, certStore, attrStore, crlStore);
      signedData = CMSSignedData.replaceSigners(signedData, new SignerInformationStore(informations));

      return ByteSource.wrap(signedData.getEncoded());
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }

  public static ASN1Set getAttributeValue(final ASN1ObjectIdentifier identifier, final AttributeTable attributeTable) {
    if (attributeTable == null) {
      return null;
    }
    Attribute attribute = attributeTable.get(identifier);
    if (attribute != null) {
      return attribute.getAttrValues();
    }
    return null;
  }

  public static byte[] getArchiveTimeStampData(final CMSSignedData cmsSignedData, final SignerInformation signerInformation) throws IOException {
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

    ContentInfo contentInfo = cmsSignedData.toASN1Structure();
    SignedData signedData = SignedData.getInstance(contentInfo.getContent());

    if ((signedData.getEncapContentInfo() == null) || (signedData.getEncapContentInfo().getContent() == null)) {
      return null;
    }

    ContentInfo content = signedData.getEncapContentInfo();
    ASN1OctetString octet = (ASN1OctetString) content.getContent();
    ContentInfo tmpContentInfo = new ContentInfo(PKCSObjectIdentifiers.data, octet);
    outputStream.write(tmpContentInfo.getEncoded());

    ASN1Set certificates = signedData.getCertificates();
    if (certificates != null) {
      ASN1OutputStream output = ASN1OutputStream.create(outputStream, ASN1Encoding.DER);
      output.writeObject(certificates);
      output.close();
    }

    ASN1Set crls = signedData.getCRLs();
    if (crls != null) {
      outputStream.write(crls.getEncoded());
    }

    SignerInformation si = CadesServiceHelper.removeOtherTimeStamps(signerInformation);
    SignerInfo signerInfo = si.toASN1Structure();
    outputStream.write(signerInfo.getEncoded());

    return outputStream.toByteArray();
  }

  private static SignerInformation removeOtherTimeStamps(final SignerInformation signerInformation) {
    AttributeTable unsigned = signerInformation.getUnsignedAttributes();
    ASN1EncodableVector currentVector = unsigned.toASN1EncodableVector();
    ASN1EncodableVector newVector = new ASN1EncodableVector();
    for (int i = 0; i < currentVector.size(); i++) {
      ASN1Encodable encodable = currentVector.get(i);
      Attribute attribute = (Attribute) encodable;
      if (attribute.getAttrType().equals(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken)) {
        continue;
      }
      if (attribute.getAttrType().equals(PKCSObjectIdentifiers.id_aa_ets_escTimeStamp)) {
        continue;
      }
      if (attribute.getAttrType().equals(ESFAttributes.archiveTimestampV2)) {
        continue;
      }
      newVector.add(attribute);
    }
    AttributeTable newUnsignedAtts = new AttributeTable(newVector);
    return SignerInformation.replaceUnsignedAttributes(signerInformation, newUnsignedAtts);
  }

  public static RevocationValues toRevocationValues(final List<Certificate> chain, final Map<Certificate, CertificateRevocationData> revocations, boolean requireFirst) throws GeneralSecurityException, IOException {
    List<CertificateList> crlList = new ArrayList<>();
    List<BasicOCSPResponse> ocspList = new ArrayList<>();

    for (int i = 0; i < chain.size(); i++) {
      Certificate certificate = chain.get(i);

      CertificateRevocationData revocationData = revocations.get(certificate);
      CRL crl = null;
      byte[] ocspBytes = null;
      if (revocationData != null) {
        crl = revocationData.getCrl();
        ocspBytes = revocationData.getOcsp();
      }

      if ((requireFirst) && (i == 0) && (crl == null) && (ocspBytes == null)) {
        X509Certificate x509Certificate = (X509Certificate) certificate;
        throw new IllegalStateException("CRL/OCSP not found for " + Certificates.toString(x509Certificate.getSubjectX500Principal()));
      }

      if (crl != null) {
        CertificateList cl = CertificateList.getInstance(((X509CRL) crl).getEncoded());
        crlList.add(cl);
      }

      if (ocspBytes != null) {
        BasicOCSPResponse basicOcspResponse = BasicOCSPResponse.getInstance(ocspBytes);
        BasicOCSPResp basicOcspResp = new BasicOCSPResp(basicOcspResponse);
        ocspList.add(BasicOCSPResponse.getInstance(basicOcspResp.getEncoded()));
      }
    }

    // org.bouncycastle.asn1.x509.Certificate[] certificateArray =
    // Iterables.toArray(certificateList,
    // org.bouncycastle.asn1.x509.Certificate.class);
    CertificateList[] crlArray = Iterables.toArray(crlList, CertificateList.class);
    BasicOCSPResponse[] ocspArray = Iterables.toArray(ocspList, BasicOCSPResponse.class);

    RevocationValues revocationValues = new RevocationValues(crlArray, ocspArray, null);
    return revocationValues;
  }

}
