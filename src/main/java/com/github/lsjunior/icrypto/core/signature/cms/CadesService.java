package com.github.lsjunior.icrypto.core.signature.cms;

import java.io.File;
import java.io.Serializable;
import java.security.PublicKey;
import java.security.cert.CRL;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAKey;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.esf.CommitmentTypeIndication;
import org.bouncycastle.asn1.esf.OtherHashAlgAndValue;
import org.bouncycastle.asn1.esf.SigPolicyQualifierInfo;
import org.bouncycastle.asn1.esf.SigPolicyQualifiers;
import org.bouncycastle.asn1.esf.SignaturePolicyId;
import org.bouncycastle.asn1.esf.SignaturePolicyIdentifier;
import org.bouncycastle.asn1.esf.SignerLocation;
import org.bouncycastle.asn1.ess.ContentHints;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SimpleAttributeTableGenerator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.util.Store;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.ICryptoException;
import com.github.lsjunior.icrypto.ICryptoLog;
import com.github.lsjunior.icrypto.api.model.CertificateRevocationData;
import com.github.lsjunior.icrypto.api.model.Document;
import com.github.lsjunior.icrypto.api.model.ErrorMessage;
import com.github.lsjunior.icrypto.api.model.LocationName;
import com.github.lsjunior.icrypto.api.model.Signature;
import com.github.lsjunior.icrypto.api.model.SignatureConstraint;
import com.github.lsjunior.icrypto.api.model.SignatureId;
import com.github.lsjunior.icrypto.api.model.SignaturePolicy;
import com.github.lsjunior.icrypto.api.model.TimeStamp;
import com.github.lsjunior.icrypto.api.type.DigestType;
import com.github.lsjunior.icrypto.api.type.RevokeReasonType;
import com.github.lsjunior.icrypto.api.type.SignatureType;
import com.github.lsjunior.icrypto.core.certificate.CertPathProvider;
import com.github.lsjunior.icrypto.core.certificate.CertificateValidator;
import com.github.lsjunior.icrypto.core.certificate.ValidationError;
import com.github.lsjunior.icrypto.core.certificate.impl.CertificateValidatorChain;
import com.github.lsjunior.icrypto.core.certificate.impl.DateCertificateValidator;
import com.github.lsjunior.icrypto.core.certificate.impl.PkixCertificateValidator;
import com.github.lsjunior.icrypto.core.certificate.impl.SelfSignedCertificateValidator;
import com.github.lsjunior.icrypto.core.certificate.impl.X509CertificateKeyUsage;
import com.github.lsjunior.icrypto.core.certificate.util.CertPaths;
import com.github.lsjunior.icrypto.core.certificate.util.Certificates;
import com.github.lsjunior.icrypto.core.crl.CrlProvider;
import com.github.lsjunior.icrypto.core.ocsp.OcspProvider;
import com.github.lsjunior.icrypto.core.ocsp.util.Ocsps;
import com.github.lsjunior.icrypto.core.signature.cms.profile.BasicProfile;
import com.github.lsjunior.icrypto.core.util.Asn1Objects;
import com.github.lsjunior.icrypto.core.util.BcProvider;
import com.google.common.base.Strings;
import com.google.common.hash.Hashing;
import com.google.common.io.ByteSource;
import com.google.common.io.Files;

public class CadesService implements Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private static final CadesService INSTANCE = new CadesService();

  private boolean addContentHints = false;

  protected CadesService() {
    super();
  }

  public CadesSignature sign(final CadesSignatureParameters parameters) {
    try {
      ICryptoLog.getLogger().info("CadesService.sign()");
      return this.sign(CadesServiceHelper.getContext(parameters));
    } catch (ICryptoException e) {
      throw e;
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }

  private CadesSignature sign(final CadesSignatureContext context) {
    try {
      ICryptoLog.getLogger().info("CadesService.sign()");
      File file = context.getData();
      File signedFile = context.getSignedData();
      List<Certificate> chain = context.getChain();
      X509Certificate certificate = (X509Certificate) chain.get(0);

      this.beforeSign(context);

      if (context.isDataDigested()) {
        ICryptoLog.getLogger().info("Data Digest SHA256" + Files.asByteSource(file).hash(Hashing.sha256()));
        context.getSignedAttributes().put(CMSAttributes.messageDigest.getId(), new DERSet(new DEROctetString(Files.toByteArray(file))).getEncoded());
      }

      ASN1EncodableVector signedAttributesVector = CadesServiceHelper.toAttributesVector(context.getSignedAttributes());
      ASN1EncodableVector unsignedAttributesVector = CadesServiceHelper.toAttributesVector(context.getUnsignedAttributes());

      CMSTypedData content = null;
      boolean encapsulate = true;

      if (context.isDataDigested()) {
        content = new CMSAbsentContent();
        encapsulate = false;
      } else {
        content = new CMSProcessableByteArray(Files.toByteArray(file));
        if (context.isDetached()) {
          encapsulate = false;
        }
      }

      CMSSignedDataGenerator signedDataGenerator = new CMSSignedDataGenerator();
      ContentSigner contentSigner = CadesServiceHelper.getContentSigner(context.getPrivateKey(), context.getAlgorithm(), context.getSignatureProvider());
      SignerInfoGeneratorBuilder signerInfoGeneratorBuilder = CadesServiceHelper.getSignerInfoGeneratorBuilder();
      signerInfoGeneratorBuilder.setSignedAttributeGenerator(CadesServiceHelper.getCmsAttributeTableGenerator(new AttributeTable(signedAttributesVector), context.isIgnoreSigningTime()));
      signerInfoGeneratorBuilder.setUnsignedAttributeGenerator(new SimpleAttributeTableGenerator(new AttributeTable(unsignedAttributesVector)));
      SignerInfoGenerator signerInfoGenerator = signerInfoGeneratorBuilder.build(contentSigner, Certificates.toCertificateHolder(certificate));
      // SignerInfo signerInfo = signerInfoGenerator.generate(content.getContentType());
      // context.setSignerId(CadesServiceHelper.getSID(signerInfo));

      // JcaSimpleSignerInfoGeneratorBuilder signerInfoGeneratorBuilder = new
      // JcaSimpleSignerInfoGeneratorBuilder();
      // signerInfoGeneratorBuilder.setProvider(context.getSignatureProvider());
      // signerInfoGeneratorBuilder.setSignedAttributeGenerator(new
      // DefaultSignedAttributeTableGenerator(new AttributeTable(signedAttributesVector)));
      // signerInfoGeneratorBuilder.setUnsignedAttributeGenerator(new
      // SimpleAttributeTableGenerator(new AttributeTable(unsignedAttributesVector)));
      // SignerInfoGenerator signerInfoGenerator = signerInfoGeneratorBuilder.build(context.getAlgorithm(), context.getPrivateKey(), certificate);

      signedDataGenerator.addSignerInfoGenerator(signerInfoGenerator);

      CMSSignedData signedData = null;

      if (context.isDetached()) {
        signedData = signedDataGenerator.generate(content, false);
      } else {
        signedData = signedDataGenerator.generate(content, encapsulate);
      }

      SignerInformationStore signerInformationStore = signedData.getSignerInfos();
      Collection<SignerInformation> signers = signerInformationStore.getSigners();
      SignerInformation signerInformation = signers.iterator().next();
      context.setSignerId(CadesServiceHelper.getSID(signerInformation.toASN1Structure()));

      Files.write(signedData.getEncoded(), signedFile);

      this.afterSign(context);

      CadesSignature response = new CadesSignature();
      response.setAlgorithm(context.getAlgorithm());
      response.setCertificate(certificate);
      response.setChain(chain);
      response.setData(Files.asByteSource(signedFile));
      return response;
    } catch (ICryptoException e) {
      throw e;
    } catch (Throwable e) {
      throw new ICryptoException(e);
    }
  }
  // @formatter:off
  /*
  public SignatureResponse coSign(final CadesSignatureParameters parameters) {
    try {
      return this.coSign(CadesServiceHelper.getContext(parameters));
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }

  private SignatureResponse coSign(final CadesSignatureContext context) {
    try {
      byte[] data = context.getData();

      CMSSignedData signedData = new CMSSignedData(data);
      CMSTypedData content = signedData.getSignedContent();
      CMSSignedDataGenerator signedDataGenerator = new CMSSignedDataGenerator();

      signedDataGenerator.addSigners(signedData.getSignerInfos());

      List<Certificate> chain = context.getChain();
      Certificate certificate = chain.get(0);

      ContentSigner contentSigner = CadesServiceHelper.getContentSigner(context.getPrivateKey(), context.getAlgorithm(), context.getSignatureProvider());

      SignerInfoGeneratorBuilder signerInfoGeneratorBuilder = CadesServiceHelper.getSignerInfoGeneratorBuilder();

      this.beforeSign(context);

      if (context.isDataDigested()) {
        context.getSignedAttributes().put(CMSAttributes.messageDigest.getId(), new DERSet(new DEROctetString(context.getData())).getEncoded());
      }

      ASN1EncodableVector signedAttributesVector = CadesServiceHelper.toAttributesVector(context.getSignedAttributes());
      ASN1EncodableVector unsignedAttributesVector = CadesServiceHelper.toAttributesVector(context.getUnsignedAttributes());

      signerInfoGeneratorBuilder.setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(new AttributeTable(signedAttributesVector)));
      signerInfoGeneratorBuilder.setUnsignedAttributeGenerator(new SimpleAttributeTableGenerator(new AttributeTable(unsignedAttributesVector)));

      SignerInfoGenerator signerInfoGenerator = signerInfoGeneratorBuilder.build(contentSigner, Certificates.toCertificateHolder(certificate));

      SignerInfo signerInfo = signerInfoGenerator.generate(content.getContentType());
      context.setSignerId(CadesServiceHelper.getSID(signerInfo));

      signedDataGenerator.addSignerInfoGenerator(signerInfoGenerator);

      if (context.isDetached()) {
        signedData = signedDataGenerator.generate(content, false);
      } else {
        signedData = signedDataGenerator.generate(content, true);
      }

      context.setSignedData(signedData.getEncoded());

      this.afterSign(context);

      SignatureResponse response = new SignatureResponse();
      response.setAlgorithm(context.getAlgorithm());
      response.setChain(chain);
      response.setData(data);
      response.setSignedData(context.getSignedData());
      return response;
    } catch (ICryptoException e) {
      throw e;
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }

  public SignatureResponse counterSign(final CadesSignatureParameters parameters) {
    try {
      return this.counterSign(CadesServiceHelper.getContext(parameters));
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }

  @SuppressWarnings({"unchecked", "rawtypes"})
  private SignatureResponse counterSign(final CadesSignatureContext context) {
    SignatureId signatureId = context.getSignatureId();

    if (signatureId == null) {
      throw new ICryptoException("Counter signature ID is null");
    }

    try {
      byte[] data = context.getData();

      CMSSignedData signedData = new CMSSignedData(data);

      SignerInformationStore signerInformationStore = signedData.getSignerInfos();
      SignerInformation toCounterInformation =
          CadesServiceHelper.getSignerInformation(signerInformationStore, signatureId.getCertificate(), signatureId.getIndex());

      if (toCounterInformation == null) {
        throw new ICryptoException("Signer information not found");
      }

      CMSTypedData content = new CMSAbsentContent();
      CMSSignedDataGenerator signedDataGenerator = new CMSSignedDataGenerator();

      List<Certificate> chain = context.getChain();
      Certificate certificate = chain.get(0);

      ContentSigner contentSigner = CadesServiceHelper.getContentSigner(context.getPrivateKey(), context.getAlgorithm(), context.getSignatureProvider());

      SignerInfoGeneratorBuilder signerInfoGeneratorBuilder = CadesServiceHelper.getSignerInfoGeneratorBuilder();

      this.beforeSign(context);

      ASN1EncodableVector signedAttributesVector = CadesServiceHelper.toAttributesVector(context.getSignedAttributes());
      ASN1EncodableVector unsignedAttributesVector = CadesServiceHelper.toAttributesVector(context.getUnsignedAttributes());

      Attribute attribute = new Attribute(CMSAttributes.counterSignature, new DERSet(toCounterInformation.toASN1Structure()));
      unsignedAttributesVector.add(attribute);

      signerInfoGeneratorBuilder.setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(new AttributeTable(signedAttributesVector)));
      signerInfoGeneratorBuilder.setUnsignedAttributeGenerator(new SimpleAttributeTableGenerator(new AttributeTable(unsignedAttributesVector)));

      SignerInfoGenerator signerInfoGenerator = signerInfoGeneratorBuilder.build(contentSigner, Certificates.toCertificateHolder(certificate));

      SignerInfo signerInfo = signerInfoGenerator.generate(content.getContentType());
      context.setSignerId(CadesServiceHelper.getSID(signerInfo));

      signedDataGenerator.addSignerInfoGenerator(signerInfoGenerator);

      SignerInformationStore counterSignerInformationStore = signedDataGenerator.generateCounterSigners(toCounterInformation);
      SignerInformation counterSignerInformation = counterSignerInformationStore.getSigners().iterator().next();

      AttributeTable unsigned = toCounterInformation.getUnsignedAttributes();
      Hashtable<ASN1ObjectIdentifier, Attribute> hashtable = null;

      if (unsigned == null) {
        hashtable = new Hashtable<>();
      } else {
        hashtable = unsigned.toHashtable();
      }

      Attribute counterSignatureAttribute = hashtable.get(CMSAttributes.counterSignature);
      if (counterSignatureAttribute == null) {
        counterSignatureAttribute = new Attribute(CMSAttributes.counterSignature, new DERSet(counterSignerInformation.toASN1Structure()));
      } else {
        ASN1Set currentSet = counterSignatureAttribute.getAttrValues();
        ASN1EncodableVector vector = new ASN1EncodableVector();
        for (int i = 0; i < currentSet.size(); i++) {
          vector.add(currentSet.getObjectAt(i));
        }
        vector.add(counterSignerInformation.toASN1Structure());
        DERSet newSet = new DERSet(vector);

        counterSignatureAttribute = new Attribute(CMSAttributes.counterSignature, newSet);
      }

      hashtable.put(CMSAttributes.counterSignature, counterSignatureAttribute);

      AttributeTable newUnsignedAtts = new AttributeTable(hashtable);

      SignerInformation newSignerInformation = SignerInformation.replaceUnsignedAttributes(toCounterInformation, newUnsignedAtts);

      List newSignerInfoList = new ArrayList();
      for (Object obj : signerInformationStore.getSigners()) {
        SignerInformation tmp = (SignerInformation) obj;
        if (tmp != toCounterInformation) {
          newSignerInfoList.add(tmp);
        }
      }

      newSignerInfoList.add(newSignerInformation);

      SignerInformationStore newSignerInformationStore = new SignerInformationStore(newSignerInfoList);

      signedData = CMSSignedData.replaceSigners(signedData, newSignerInformationStore);

      context.setSignerId(CadesServiceHelper.getSID(newSignerInformation.toASN1Structure()));
      context.setSignedData(signedData.getEncoded());

      this.afterSign(context);

      SignatureResponse response = new SignatureResponse();
      response.setAlgorithm(context.getAlgorithm());
      response.setChain(chain);
      response.setData(data);
      response.setSignedData(context.getSignedData());
      return response;
    } catch (ICryptoException e) {
      throw e;
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  } */
  // @formatter:on

  public CadesSignature extend(final CadesSignatureParameters parameters) {
    try {
      return this.extend(CadesServiceHelper.getContext(parameters));
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }

  @SuppressWarnings({"unchecked", "rawtypes"})
  private CadesSignature extend(final CadesSignatureContext context) {
    SignatureId counterSignatory = context.getSignatureId();
    SignatureProfile signatureProfile = context.getProfile();

    if (counterSignatory == null) {
      throw new ICryptoException("Signature to extend is null");
    }

    if (signatureProfile == null) {
      throw new ICryptoException("Signature profile is null");
    }

    try {
      File data = context.getData();
      ByteSource source = Files.asByteSource(data);
      CertPathProvider certPathProvider = context.getCertPathProvider();

      CMSSignedData signedData = new CMSSignedData(source.openStream());
      Store certificateStore = signedData.getCertificates();
      SignerInformationStore signerInformationStore = signedData.getSignerInfos();
      SignerInformation signerInformation = CadesServiceHelper.getSignerInformation(signerInformationStore, counterSignatory.getCertificate(), counterSignatory.getIndex());

      if (signerInformation == null) {
        throw new ICryptoException("Signer information not found");
      }

      SignerId signerId = signerInformation.getSID();
      Collection<X509CertificateHolder> certificateHolders = certificateStore.getMatches(signerId);
      if (certificateHolders.isEmpty()) {
        throw new ICryptoException("Unable to find certificate " + signerId.getSerialNumber() + " issued by " + Certificates.toString(signerId.getIssuer()));
      }

      X509CertificateHolder certificateHolder = (X509CertificateHolder) certificateStore.getMatches(signerId).iterator().next();

      CertPath certPath = null;
      if (certPathProvider != null) {
        certPath = certPathProvider.getCertPath(Certificates.toCertificate(certificateHolder));
      } else {
        certPath = CertPaths.toCertPath(Certificates.toCertificate(certificateHolder), Certificates.toCertificates(certificateStore.getMatches(null)));
      }

      if (certPath == null) {
        throw new ICryptoException("Unable to find CertPath");
      }

      List<Certificate> chain = CertPaths.toCertificate(certPath);
      SignatureType signatureType = Asn1Objects.getSignatureType(signerInformation.getDigestAlgOID(), signerInformation.getEncryptionAlgOID());

      context.setCertPathProvider(certPathProvider);
      context.setChain(chain);
      context.setSignedData(data);
      context.setSignerId(CadesServiceHelper.getSID(signerInformation.toASN1Structure()));
      context.setSignatureType(signatureType);

      this.afterSign(context);

      CadesSignature response = new CadesSignature();
      response.setAlgorithm(context.getAlgorithm());
      response.setChain(chain);
      response.setData(Files.asByteSource(context.getSignedData()));
      return response;
    } catch (ICryptoException e) {
      throw e;
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }
  // @formatter:on

  private void beforeSign(final CadesSignatureContext context) {
    this.validateSignContext(context);
    try {
      SignaturePolicy policy = context.getPolicy();
      // SignatureVersion version = policy != null ? policy.getSignatureVersion() : SignatureVersion.V2;
      SignatureType signatureType = context.getSignatureType();
      DigestType digestType = signatureType.getDigestType();

      // FIXME ver quando colocar a versao 1
      boolean useSigningCertificateV1 = false;

      List<Certificate> chain = context.getChain();
      Certificate certificate = chain.get(0);
      Certificate issuer = chain.size() > 1 ? chain.get(1) : null;

      if (useSigningCertificateV1) {
        ESSCertID certId = CadesServiceHelper.getESSCertID(certificate, issuer);
        SigningCertificate signingCertificate = new SigningCertificate(certId);
        context.getSignedAttributes().put(PKCSObjectIdentifiers.id_aa_signingCertificate.getId(), new DERSet(signingCertificate).getEncoded());
      } else {
        ESSCertIDv2 certId = CadesServiceHelper.getESSCertIDv2(certificate, issuer, digestType);
        SigningCertificateV2 signingCertificate = new SigningCertificateV2(certId);
        context.getSignedAttributes().put(PKCSObjectIdentifiers.id_aa_signingCertificateV2.getId(), new DERSet(signingCertificate).getEncoded());
      }

      String commitmentType = context.getCommitmentType();
      if (!Strings.isNullOrEmpty(commitmentType)) {
        ASN1ObjectIdentifier commitmentTypeId = new ASN1ObjectIdentifier(commitmentType);
        CommitmentTypeIndication commitmentTypeIndication = new CommitmentTypeIndication(commitmentTypeId);
        context.getSignedAttributes().put(PKCSObjectIdentifiers.id_aa_ets_commitmentType.getId(), new DERSet(commitmentTypeIndication).getEncoded());
      }

      LocationName locationName = context.getLocationName();
      if (locationName != null) {
        SignerLocation signerLocation = new SignerLocation(new DERUTF8String(locationName.getCountryName()), new DERUTF8String(locationName.getLocalityName()), null);
        context.getSignedAttributes().put(PKCSObjectIdentifiers.id_aa_ets_signerLocation.getId(), new DERSet(signerLocation).getEncoded());
      }

      TimeStamp contentTimeStamp = context.getContentTimeStamp();
      if (contentTimeStamp != null) {
        ASN1Primitive asn1Primitive = Asn1Objects.toAsn1Primitive(contentTimeStamp.getEncoded());
        context.getSignedAttributes().put(PKCSObjectIdentifiers.id_aa_ets_contentTimestamp.getId(), new DERSet(asn1Primitive).getEncoded());
      }

      if ((policy != null) && (!Strings.isNullOrEmpty(policy.getPolicyId())) && (policy.getDigestType() != null) && (policy.getDigestValue() != null)) {
        ASN1ObjectIdentifier policyId = new ASN1ObjectIdentifier(policy.getPolicyId());
        AlgorithmIdentifier hashAlgorithm = Asn1Objects.getAlgorithmIdentifier(policy.getDigestType());
        ASN1OctetString hashValue = new DEROctetString(policy.getDigestValue());
        OtherHashAlgAndValue policyHash = new OtherHashAlgAndValue(hashAlgorithm, hashValue);

        SignaturePolicyId signaturePolicyId = null;
        if (!Strings.isNullOrEmpty(policy.getPolicyUrl())) {
          SigPolicyQualifierInfo qualifierInfo = new SigPolicyQualifierInfo(PKCSObjectIdentifiers.id_spq_ets_uri, new DERIA5String(policy.getPolicyUrl()));
          SigPolicyQualifiers qualifiers = new SigPolicyQualifiers(new SigPolicyQualifierInfo[] {qualifierInfo});
          signaturePolicyId = new SignaturePolicyId(policyId, policyHash, qualifiers);
        } else {
          signaturePolicyId = new SignaturePolicyId(policyId, policyHash);
        }

        SignaturePolicyIdentifier signaturePolicyIdentifier = new SignaturePolicyIdentifier(signaturePolicyId);

        context.getSignedAttributes().put(PKCSObjectIdentifiers.id_aa_ets_sigPolicyId.getId(), new DERSet(signaturePolicyIdentifier).getEncoded());
      }

      // TODO ????
      // org.bouncycastle.asn1.x509.Attribute[] attributes = new
      // org.bouncycastle.asn1.x509.Attribute[0];
      // SignerAttribute signerAttribute = new SignerAttribute(attributes);

      // context.getSignedAttributes().put(PKCSObjectIdentifiers.id_aa_ets_signerAttr.getId(), new
      // DERSet(signerAttribute).getEncoded());

      String contentName = context.getContentName();
      String contentType = context.getContentType();
      if ((this.addContentHints) && (!Strings.isNullOrEmpty(contentName)) && (!Strings.isNullOrEmpty(contentName))) {
        // See CAdESLevelBaselineB.java
        DERUTF8String description = CadesServiceHelper.getContentHint(contentName, contentType);
        ContentHints contentHints = new ContentHints(PKCSObjectIdentifiers.data, description);

        context.getSignedAttributes().put(CMSAttributes.contentHint.getId(), new DERSet(contentHints).getEncoded());

        // context.getSignedAttributes().put(MicrosoftObjectIdentifiers.microsoft.branch("2.1").getId(),
        // new DERSet(new DEROctetString(contentName.getBytes())).getEncoded());
      }
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }

  private void afterSign(final CadesSignatureContext context) {
    context.getProfile().extend(context);
  }

  // Validation
  private void validateSignContext(final CadesSignatureContext context) {
    this.validateCertificate(context);
    this.validateSignatureConstraint(context);
    this.validateDate(context);
    this.validateCrlAndOcsp(context);
  }

  private void validateCertificate(final CadesSignatureContext context) {
    CertificateValidator cv = this.getCertificateValidator();
    List<Certificate> chain = context.getChain();
    Certificate certificate = chain.get(0);

    if (cv != null) {
      Collection<ValidationError> errors = cv.validate(chain);
      if ((errors != null) && (!errors.isEmpty())) {
        throw new ICryptoException(errors.iterator().next().getMessage());
      }
    }

    X509CertificateKeyUsage keyUsage = X509CertificateKeyUsage.getInstance(certificate);

    if (!keyUsage.isKeyUsageDigitalSignature()) {
      throw new ICryptoException("Certificate dont has digital signature key usage");
    }
  }

  private CertificateValidator getCertificateValidator() {
    CertificateValidatorChain cv = new CertificateValidatorChain();
    cv.add(new DateCertificateValidator());
    cv.add(new SelfSignedCertificateValidator());
    cv.add(new PkixCertificateValidator(BcProvider.PROVIDER_NAME));
    // see validateCrlAndOcsp
    // cv.add(new OCSPCertificateValidator());
    // cv.add(new CRLCertificateValidator());
    return cv;
  }

  private void validateSignatureConstraint(final CadesSignatureContext context) {
    SignaturePolicy c = context.getPolicy();
    if (c != null) {
      List<Certificate> chain = context.getChain();
      Certificate certificate = chain.get(0);
      PublicKey publicKey = certificate.getPublicKey();
      if (publicKey instanceof RSAKey) {
        RSAKey rsaKey = (RSAKey) publicKey;
        int keySize = rsaKey.getModulus().bitLength();
        SignatureType type = context.getSignatureType();
        Set<SignatureConstraint> constraints = c.getSignatureConstraints();
        boolean ok = false;
        if (constraints != null) {
          for (SignatureConstraint sc : constraints) {
            if ((sc.getSignatureType() == type) && (keySize >= sc.getMinKeySize())) {
              ok = true;
              break;
            }
          }
        }
        if (!ok) {
          throw new ICryptoException("Invalid signature type " + type + " with key size " + keySize);
        }
      } else if (publicKey instanceof ECPublicKey) {
        // ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
        SignatureType type = context.getSignatureType();
        Set<SignatureConstraint> constraints = c.getSignatureConstraints();
        boolean ok = false;
        if (constraints != null) {
          for (SignatureConstraint sc : constraints) {
            if (sc.getSignatureType() == type) {
              ok = true;
              break;
            }
          }
        }
        if (!ok) {
          throw new ICryptoException("Invalid signature type " + type);
        }
      } else {
        throw new ICryptoException("Unsupported public key " + publicKey.getAlgorithm());
      }
    }
  }

  private void validateDate(final CadesSignatureContext context) {
    SignaturePolicy c = context.getPolicy();
    if (c != null) {
      Date date = context.getDate();

      if (date == null) {
        date = new Date();
      }

      Date notBefore = c.getNotBefore();
      Date notAfter = c.getNotAfter();
      if ((notBefore == null) || (notAfter == null)) {
        throw new ICryptoException("Invalid signature period");
      }
      if ((date.before(notBefore)) || (date.after(notAfter))) {
        throw new ICryptoException("Invalid signature period");
      }

      List<Certificate> chain = context.getChain();
      Certificate certificate = chain.get(0);
      X509Certificate x509Certificate = (X509Certificate) certificate;

      notBefore = x509Certificate.getNotBefore();
      notAfter = x509Certificate.getNotAfter();

      if ((date.before(notBefore)) || (date.after(notAfter))) {
        throw new ICryptoException("Invalid signature period");
      }
    }
  }

  private void validateCrlAndOcsp(final CadesSignatureContext context) {
    try {
      if ((context.getValidateCertificate() != null) && (context.getValidateCertificate().booleanValue())) {
        List<Certificate> chain = context.getChain();
        CrlProvider crlProvider = context.getCrlProvider();
        OcspProvider ocspProvider = context.getOcspProvider();

        Map<Certificate, CertificateRevocationData> revocations = context.getRevocations();
        if (revocations == null) {
          revocations = CadesServiceHelper.getCrlAndOcsps(chain, crlProvider, ocspProvider);
          context.setRevocations(revocations);
        }

        for (int i = 0; i < chain.size(); i++) {
          Certificate certificate = chain.get(i);
          CertificateRevocationData revocationData = revocations.get(certificate);

          CRL crl = revocationData != null ? revocationData.getCrl() : null;
          byte[] ocspBytes = revocationData != null ? revocationData.getOcsp() : null;

          if ((i == 0) && (crl == null) && (ocspBytes == null)) {
            X509Certificate x509Certificate = (X509Certificate) certificate;
            throw new IllegalStateException("CRL/OCSP not found for " + Certificates.toString(x509Certificate.getSubjectX500Principal()));
          }

          if (crl != null) {
            if (crl.isRevoked(certificate)) {
              throw new IllegalStateException("Certificate is revoked");
            }
          }

          if (ocspBytes != null) {
            BasicOCSPResponse basicOcspResponse = BasicOCSPResponse.getInstance(ocspBytes);
            BasicOCSPResp basicOcspResp = new BasicOCSPResp(basicOcspResponse);

            RevokeReasonType revokeReason = Ocsps.isRevoked(basicOcspResp);
            if (revokeReason != null) {
              throw new IllegalStateException("Certificate is revoked with status " + revokeReason.toString());
            }
          }
        }
      }
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }

  public CadesVerificationResult verify(final CadesVerificationParameters request) {
    try {
      // FIXME
      ByteSource data = request.getData();
      ByteSource signature = request.getSignature();
      ByteSource content = CadesServiceHelper.getContent(signature);

      if ((data == null) && (content == null)) {
        throw new ICryptoException("CMS not has content and request data is empty");
      }

      List<Certificate> chain = request.getChain();
      CertPathProvider certPathProvider = request.getCertPathProvider();
      SignaturePolicyProvider signaturePolicyProvider = request.getSignaturePolicyProvider();
      SignatureProfile profile = request.getSignatureProfile();

      CMSSignedData cmsSignedData = null;
      if (content != null) {
        cmsSignedData = new CMSSignedData(signature.openStream());
      } else {
        // TODO Mudar para file, nao em memoria!!!
        cmsSignedData = new CMSSignedData(new CMSProcessableByteArray(data.read()), signature.read());
      }

      if (profile == null) {
        profile = new BasicProfile();
      }

      Document document = CadesServiceHelper.toDocument(cmsSignedData, certPathProvider, signaturePolicyProvider, chain);
      List<Signature> signatures = document.getSignatures();
      boolean valid = true;

      if (signatures != null) {
        VerificationContext context = new VerificationContext();
        context.setCertPathProvider(certPathProvider);
        context.setDocument(document);

        for (Signature sig : signatures) {
          context.setSignature(sig);
          profile.verify(context);

          if (!sig.isValid()) {
            document.getErrors().addAll(sig.getErrors());
            valid = false;
          }
        }
      } else {
        document.getErrors().add(new ErrorMessage(CadesErrors.SIGNATURE_EMPTY, "Signed data don't contains any signature", true));
        valid = false;
      }

      CadesVerificationResult response = new CadesVerificationResult();
      response.setDocument(document);
      response.setValid(valid);
      return response;
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }

  public ByteSource merge(final List<ByteSource> signatures) {
    return CadesServiceHelper.merge(signatures);
  }

  public static CadesService getInstance() {
    return CadesService.INSTANCE;
  }

}
