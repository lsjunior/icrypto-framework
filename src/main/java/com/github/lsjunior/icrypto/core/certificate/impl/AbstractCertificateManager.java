package com.github.lsjunior.icrypto.core.certificate.impl;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map.Entry;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.misc.NetscapeCertType;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

import com.github.lsjunior.icrypto.api.model.AlternativeNameType;
import com.github.lsjunior.icrypto.api.model.SubjectAlternativeName;
import com.github.lsjunior.icrypto.api.type.ExtendedKeyUsageType;
import com.github.lsjunior.icrypto.api.type.KeyUsageType;
import com.google.common.base.Strings;
import com.google.common.collect.Iterables;

public abstract class AbstractCertificateManager {

  private static final ASN1ObjectIdentifier ANY_POLICY = Extension.certificatePolicies.branch("0");

  public AbstractCertificateManager() {
    super();
  }

  protected Extension getKeyUsage(final BouncyCastleCertificateRequest request) throws IOException {
    int usage = 0;
    if (!request.getKeyUsage().isEmpty()) {
      for (KeyUsageType keyUsage : request.getKeyUsage()) {
        usage = usage | keyUsage.getUsage();
      }
    }

    org.bouncycastle.asn1.x509.KeyUsage ku = new org.bouncycastle.asn1.x509.KeyUsage(usage);
    Extension extension = new Extension(Extension.keyUsage, true, ku.getEncoded(ASN1Encoding.DER));
    return extension;
  }

  protected Extension getExtendedKeyUsage(final BouncyCastleCertificateRequest request) throws IOException {
    if (!request.getExtendedKeyUsage().isEmpty()) {
      List<KeyPurposeId> list = new ArrayList<>();
      for (ExtendedKeyUsageType keyUsageType : request.getExtendedKeyUsage()) {
        KeyPurposeId keyPurposeId = keyUsageType.getKeyPurposeId();
        list.add(keyPurposeId);
      }
      if (list.size() > 0) {
        org.bouncycastle.asn1.x509.ExtendedKeyUsage extendedKeyUsage =
            new org.bouncycastle.asn1.x509.ExtendedKeyUsage(Iterables.toArray(list, KeyPurposeId.class));
        Extension extension = new Extension(Extension.extendedKeyUsage, request.isExtendedKeyUsageCritical(), extendedKeyUsage.getEncoded(ASN1Encoding.DER));
        return extension;
      }
    }
    return null;
  }

  protected Extension getCertificatePolicies(final BouncyCastleCertificateRequest request) throws IOException {
    if (request.getCertificatePolicies() != null) {
      List<PolicyInformation> list = new ArrayList<>();
      for (Entry<String, String> entry : request.getCertificatePolicies().entrySet()) {
        String oid = entry.getKey();
        String value = entry.getValue();
        ASN1ObjectIdentifier policyIdentifier = new ASN1ObjectIdentifier(oid);
        PolicyQualifierInfo policyQualifierInfo = new PolicyQualifierInfo(policyIdentifier, new DERIA5String(value));
        DERSequence policyQualifiers = new DERSequence(new ASN1Encodable[] {policyQualifierInfo});
        PolicyInformation policyInformation = new PolicyInformation(policyIdentifier, policyQualifiers);
        list.add(policyInformation);
      }

      CertificatePolicies certificatePolicies = new CertificatePolicies(Iterables.toArray(list, PolicyInformation.class));
      Extension extension = new Extension(Extension.certificatePolicies, false, certificatePolicies.getEncoded(ASN1Encoding.DER));
      return extension;
    }
    PolicyInformation information = new PolicyInformation(AbstractCertificateManager.ANY_POLICY);
    CertificatePolicies certificatePolicies = new CertificatePolicies(information);
    Extension extension = new Extension(Extension.certificatePolicies, false, certificatePolicies.getEncoded(ASN1Encoding.DER));
    return extension;
  }

  protected Extension getOtherNames(final BouncyCastleCertificateRequest request) throws IOException {
    if (request.getAlternativeNames() != null) {
      ASN1EncodableVector vector = new ASN1EncodableVector();

      for (SubjectAlternativeName alternativeName : request.getAlternativeNames()) {
        String oid = alternativeName.getId();
        String value = alternativeName.getValue();
        if (value != null) {
          if (alternativeName.getType() == AlternativeNameType.DNS_NAME) {
            GeneralName name = new GeneralName(GeneralName.dNSName, value);
            vector.add(name);
          } else if (alternativeName.getType() == AlternativeNameType.OTHER_NAME) {
            ASN1ObjectIdentifier identifier = new ASN1ObjectIdentifier(oid);
            DEROctetString octetString = new DEROctetString(value.getBytes());
            DERTaggedObject taggedObject = new DERTaggedObject(BERTags.OCTET_STRING, octetString);
            DERSequence sequence = new DERSequence(new ASN1Encodable[] {identifier, taggedObject});
            GeneralName name = new GeneralName(GeneralName.otherName, sequence);
            vector.add(name);
          }
          if (alternativeName.getType() == AlternativeNameType.RFC_822_NAME) {
            GeneralName name = new GeneralName(GeneralName.rfc822Name, value);
            vector.add(name);
          }
        }
      }

      if (vector.size() > 0) {
        GeneralNames subjectAltName = GeneralNames.getInstance(new DERSequence(vector));
        Extension extension = new Extension(Extension.subjectAlternativeName, false, subjectAltName.getEncoded(ASN1Encoding.DER));
        return extension;
      }
    }
    return null;
  }

  protected Extension getCrlDistPoint(final BouncyCastleCertificateRequest request) throws IOException {
    if (!Strings.isNullOrEmpty(request.getCrlDistPoint())) {
      GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(request.getCrlDistPoint()));

      ASN1EncodableVector vec = new ASN1EncodableVector();
      vec.add(gn);

      GeneralNames generalNames = GeneralNames.getInstance(new DERSequence(vec));
      DistributionPointName distributionPointName = new DistributionPointName(0, generalNames);
      CRLDistPoint crlDistPoint = new CRLDistPoint(new DistributionPoint[] {new DistributionPoint(distributionPointName, null, null)});

      Extension extension = new Extension(Extension.cRLDistributionPoints, false, crlDistPoint.getEncoded(ASN1Encoding.DER));
      return extension;
    }
    return null;
  }

  protected Extension getNetscapeCertType(final BouncyCastleCertificateRequest request) throws IOException {
    int usage = 0;
    if (!request.getKeyUsage().isEmpty()) {
      for (KeyUsageType keyUsage : request.getKeyUsage()) {
        if (keyUsage == KeyUsageType.DIGITAL_SIGNATURE) {
          usage |= NetscapeCertType.objectSigning;
        }
      }
      if (usage != NetscapeCertType.objectSigning) {
        for (ExtendedKeyUsageType extendedKeyUsage : request.getExtendedKeyUsage()) {
          if (extendedKeyUsage == ExtendedKeyUsageType.CLIENT_AUTH) {
            usage |= NetscapeCertType.sslClient;
          } else if (extendedKeyUsage == ExtendedKeyUsageType.EMAIL_PROTECTION) {
            usage |= NetscapeCertType.smime;
          } else if (extendedKeyUsage == ExtendedKeyUsageType.SERVER_AUTH) {
            usage |= NetscapeCertType.sslServer;
          }
        }
      }
    }

    Extension extension = new Extension(MiscObjectIdentifiers.netscapeCertType, false, new NetscapeCertType(usage).getEncoded(ASN1Encoding.DER));
    return extension;
  }

  protected Extension getNetscapeCaPolicyUrl(final BouncyCastleCertificateRequest request) throws IOException {
    if (!Strings.isNullOrEmpty(request.getCrlDistPoint())) {
      Extension extension =
          new Extension(MiscObjectIdentifiers.netscapeCApolicyURL, false, new DERIA5String(request.getCrlDistPoint()).getEncoded(ASN1Encoding.DER));
      return extension;
    }
    return null;
  }

  protected Extension getOcspNoCheck(final BouncyCastleCertificateRequest request) throws IOException {
    if (request.getExtendedKeyUsage().contains(ExtendedKeyUsageType.OCSP_SIGNING)) {
      ASN1Null asn1Null = DERNull.INSTANCE;
      Extension extension = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck, false, asn1Null.getEncoded(ASN1Encoding.DER));
      return extension;
    }
    return null;
  }

  protected Extension getOcspUrl(final BouncyCastleCertificateRequest request) throws IOException {
    if (!Strings.isNullOrEmpty(request.getOcspUrl())) {
      GeneralName ocspLocation = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(request.getOcspUrl()));
      Extension extension = new Extension(Extension.authorityInfoAccess, false,
          new AuthorityInformationAccess(X509ObjectIdentifiers.ocspAccessMethod, ocspLocation).getEncoded(ASN1Encoding.DER));
      return extension;
    }
    return null;
  }

  protected Extension getPolicyUrl(final BouncyCastleCertificateRequest request) throws IOException {
    if (!Strings.isNullOrEmpty(request.getPolicyUrl())) {
      Extension extension =
          new Extension(MiscObjectIdentifiers.netscapeCApolicyURL, false, new DERIA5String(request.getPolicyUrl()).getEncoded(ASN1Encoding.DER));
      return extension;
    }
    return null;
  }

  protected Extension getComment(final BouncyCastleCertificateRequest request) throws IOException {
    if (!Strings.isNullOrEmpty(request.getComment())) {
      Extension extension =
          new Extension(MiscObjectIdentifiers.netscapeCertComment, false, new DERIA5String(request.getComment()).getEncoded(ASN1Encoding.DER));
      return extension;
    }
    return null;
  }

  protected Extension getBasicConstraints(final BouncyCastleCertificateRequest request) throws IOException {
    BasicConstraints basicConstraints = null;
    if (request.isBasicConstraintsCritical()) {
      if (request.getIssuer() == null) {
        basicConstraints = new BasicConstraints(true);
      } else {
        ASN1Boolean asn1Boolean = ASN1Boolean.TRUE;
        ASN1Integer asn1Integer = new ASN1Integer(0);
        ASN1Encodable[] array = new ASN1Encodable[] {asn1Boolean, asn1Integer};
        ASN1Sequence sequence = new DERSequence(array);
        basicConstraints = BasicConstraints.getInstance(sequence);
      }
    } else {
      basicConstraints = new BasicConstraints(false);
    }
    byte[] extValue = basicConstraints.getEncoded(ASN1Encoding.DER);
    Extension extension = new Extension(Extension.basicConstraints, true, extValue);
    return extension;
  }

}
