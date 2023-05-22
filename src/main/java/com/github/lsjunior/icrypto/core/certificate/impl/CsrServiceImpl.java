package com.github.lsjunior.icrypto.core.certificate.impl;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;

import com.github.lsjunior.icrypto.ICryptoException;
import com.github.lsjunior.icrypto.api.model.AlternativeNameType;
import com.github.lsjunior.icrypto.api.model.SubjectAlternativeName;
import com.github.lsjunior.icrypto.api.type.ExtendedKeyUsageType;
import com.github.lsjunior.icrypto.api.type.KeyUsageType;
import com.github.lsjunior.icrypto.core.certificate.CertificateExtension;
import com.github.lsjunior.icrypto.core.certificate.CertificateParameters;
import com.github.lsjunior.icrypto.core.certificate.CsrService;
import com.github.lsjunior.icrypto.core.certificate.util.Certificates;
import com.github.lsjunior.icrypto.core.util.Asn1Objects;

public class CsrServiceImpl extends AbstractCertificateManager implements CsrService {

  private static CsrServiceImpl instance = new CsrServiceImpl();

  protected CsrServiceImpl() {
    super();
  }

  @Override
  public CertificateParameters parse(final byte[] csr) {
    try {
      PKCS10CertificationRequest pkcs10CertificationRequest = new PKCS10CertificationRequest(csr);
      CertificateParameters certificateRequest = new CertificateParameters(Certificates.toDistinguishedName(pkcs10CertificationRequest.getSubject()));
      for (Attribute attribute : pkcs10CertificationRequest.getAttributes()) {
        if (attribute.getAttrType().getId().equals(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest.getId())) {
          ASN1Set asn1Set = attribute.getAttrValues();
          Extensions extensions = Extensions.getInstance(asn1Set.getObjectAt(0));
          ASN1ObjectIdentifier[] extensionIdentifiers = extensions.getExtensionOIDs();
          for (ASN1ObjectIdentifier extensionIdentifier : extensionIdentifiers) {
            Extension extension = extensions.getExtension(extensionIdentifier);
            if (extension.getExtnId().getId().equals(Extension.basicConstraints.getId())) {
              BasicConstraints basicConstraints = BasicConstraints.getInstance(extension.getExtnValue().getOctets());
              certificateRequest.setBasicConstraintsCritical(basicConstraints.isCA());
            } else if (extension.getExtnId().getId().equals(Extension.keyUsage.getId())) {
              KeyUsage keyUsage = KeyUsage.getInstance(extension.getParsedValue());
              for (KeyUsageType keyUsageType : KeyUsageType.values()) {
                int code = keyUsageType.getUsage();
                if (keyUsage.hasUsages(code)) {
                  certificateRequest.getKeyUsage().add(keyUsageType);
                }
              }
            } else if (extension.getExtnId().getId().equals(Extension.extendedKeyUsage.getId())) {
              ExtendedKeyUsage extendedKeyUsage = ExtendedKeyUsage.getInstance(extension.getExtnValue().getOctets());
              KeyPurposeId[] keyPurposeIds = extendedKeyUsage.getUsages();
              for (KeyPurposeId keyPurposeId : keyPurposeIds) {
                certificateRequest.getExtendedKeyUsage().add(ExtendedKeyUsageType.get(keyPurposeId));
              }
            } else if (extension.getExtnId().getId().equals(Extension.certificatePolicies.getId())) {
              CertificatePolicies certificatePolicies = CertificatePolicies.getInstance(extension.getExtnValue().getOctets());
              PolicyInformation[] policyInformations = certificatePolicies.getPolicyInformation();
              for (PolicyInformation policyInformation : policyInformations) {
                ASN1Sequence policyQualifier = policyInformation.getPolicyQualifiers();
                PolicyQualifierInfo policyQualifierInfo = PolicyQualifierInfo.getInstance(policyQualifier.getObjectAt(0));
                ASN1IA5String deria5String = ASN1IA5String.getInstance(policyQualifierInfo.getQualifier());
                String oid = policyInformation.getPolicyIdentifier().getId();
                String value = deria5String.getString();
                certificateRequest.getCertificatePolicies().put(oid, value);
              }

            } else if (extension.getExtnId().getId().equals(Extension.subjectAlternativeName.getId())) {
              GeneralNames generalNames = GeneralNames.getInstance(extension.getExtnValue().getOctets());
              for (GeneralName generalName : generalNames.getNames()) {
                if (generalName.getTagNo() == GeneralName.rfc822Name) {
                  ASN1IA5String deria5String = ASN1IA5String.getInstance(generalName.getName());
                  certificateRequest.getAlternativeNames().add(new SubjectAlternativeName(deria5String.getString(), AlternativeNameType.RFC_822_NAME));
                } else if (generalName.getTagNo() == GeneralName.otherName) {
                  ASN1Sequence asn1Sequence = ASN1Sequence.getInstance(generalName.getName());
                  ASN1ObjectIdentifier asn1ObjectIdentifier = ASN1ObjectIdentifier.getInstance(asn1Sequence.getObjectAt(0));
                  ASN1TaggedObject derTaggedObject = ASN1TaggedObject.getInstance(asn1Sequence.getObjectAt(1));
                  String oid = asn1ObjectIdentifier.getId();
                  String value = Asn1Objects.toString(derTaggedObject);
                  certificateRequest.getAlternativeNames().add(new SubjectAlternativeName(oid, value, AlternativeNameType.OTHER_NAME));
                }
              }
            } else if (extension.getExtnId().getId().equals(Extension.cRLDistributionPoints.getId())) {
              CRLDistPoint crlDistPoint = CRLDistPoint.getInstance(extension.getExtnValue().getOctets());
              DistributionPoint[] distributionPoints = crlDistPoint.getDistributionPoints();
              DistributionPoint distributionPoint = distributionPoints[0];
              DistributionPointName distributionPointName = distributionPoint.getDistributionPoint();
              GeneralNames generalNames = GeneralNames.getInstance(distributionPointName.getName());
              GeneralName generalName = generalNames.getNames()[0];
              ASN1String asn1String = ASN1IA5String.getInstance(generalName.getName());
              certificateRequest.setCrlDistPoint(asn1String.getString());
            } else if (extension.getExtnId().getId().equals(Extension.authorityInfoAccess.getId())) {
              AuthorityInformationAccess authorityInformationAccess = AuthorityInformationAccess.getInstance(extension.getExtnValue().getOctets());
              AccessDescription[] accessDescriptions = authorityInformationAccess.getAccessDescriptions();
              AccessDescription accessDescription = accessDescriptions[0];
              if (accessDescription.getAccessMethod().getId().equals(X509ObjectIdentifiers.ocspAccessMethod.getId())) {
                GeneralName generalName = accessDescription.getAccessLocation();
                ASN1String asn1String = ASN1IA5String.getInstance(generalName.getName());
                certificateRequest.setOcspUrl(asn1String.getString());
              }
            } else if (extension.getExtnId().getId().equals(MiscObjectIdentifiers.netscapeCApolicyURL.getId())) {
              BasicConstraints basicConstraints = BasicConstraints.getInstance(extension.getExtnValue().getOctets());
              certificateRequest.setBasicConstraintsCritical(basicConstraints.isCA());
            } else if (extension.getExtnId().getId().equals(MiscObjectIdentifiers.netscapeCertComment.getId())) {
              ASN1String asn1String = ASN1IA5String.getInstance(extension.getExtnValue().getOctets());
              certificateRequest.setComment(asn1String.getString());
            }
          }
        }
      }
      return certificateRequest;
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }

  @Override
  public byte[] generate(final CertificateParameters request) {
    try {
      CertificateParameters r = request;
      if (request.getExtensions() != null) {
        for (CertificateExtension extensionHandler : request.getExtensions()) {
          if (extensionHandler != null) {
            r = extensionHandler.extend(r);
          }
        }
      }

      BouncyCastleCertificateRequest bcRequest = new BouncyCastleCertificateRequest(r);
      byte[] response = this.buildCertificateRequest(bcRequest);
      return response;
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }

  protected byte[] buildCertificateRequest(final BouncyCastleCertificateRequest request) throws OperatorCreationException, GeneralSecurityException, IOException {
    JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder(request.getSignatureAlgorithm());
    contentSignerBuilder.setProvider(request.getProvider());
    ContentSigner contentSigner = contentSignerBuilder.build(request.getPrivateKey());

    AlgorithmIdentifier algorithmIdentifier = Asn1Objects.getAlgorithmIdentifier(request.getSignatureType());
    SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(algorithmIdentifier, request.getPublicKey().getEncoded());
    PKCS10CertificationRequestBuilder builder = new PKCS10CertificationRequestBuilder(request.getSubjectAsX500Name(), subjectPublicKeyInfo);

    SubjectKeyIdentifier subjectKeyIdentifier = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(request.getPublicKey());

    ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
    extensionsGenerator.addExtension(Extension.subjectKeyIdentifier, false, subjectKeyIdentifier);

    List<Extension> extensions = new ArrayList<>();
    extensions.add(this.getBasicConstraints(request));
    extensions.add(this.getKeyUsage(request));
    extensions.add(this.getExtendedKeyUsage(request));
    extensions.add(this.getCertificatePolicies(request));
    extensions.add(this.getOtherNames(request));
    extensions.add(this.getComment(request));
    extensions.add(this.getCrlDistPoint(request));
    extensions.add(this.getOcspUrl(request));
    extensions.add(this.getNetscapeCertType(request));
    extensions.add(this.getNetscapeCaPolicyUrl(request));
    extensions.add(this.getPolicyUrl(request));

    for (Extension extension : extensions) {
      if (extension != null) {
        extensionsGenerator.addExtension(extension.getExtnId(), extension.isCritical(), extension.getParsedValue());
      }
    }

    builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensionsGenerator.generate());

    PKCS10CertificationRequest csr = builder.build(contentSigner);

    return csr.getEncoded();
  }

  public static CsrServiceImpl getInstance() {
    return CsrServiceImpl.instance;
  }

}
