package com.github.lsjunior.icrypto.core.certificate;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.api.model.DistinguishedName;
import com.github.lsjunior.icrypto.api.model.SubjectAlternativeName;
import com.github.lsjunior.icrypto.api.type.ExtendedKeyUsageType;
import com.github.lsjunior.icrypto.api.type.KeyPairType;
import com.github.lsjunior.icrypto.api.type.KeySizeType;
import com.github.lsjunior.icrypto.api.type.KeyUsageType;
import com.github.lsjunior.icrypto.api.type.SignatureType;
import com.github.lsjunior.icrypto.core.Identity;

public class CertificateParameters implements Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private DistinguishedName subject;

  private KeyPair keyPair;

  private KeyPairType keyPairType;

  private SignatureType signatureType;

  private Identity issuer;

  private BigInteger serialNumber;

  private Date notBefore;

  private Date notAfter;

  private String comment;

  private String crlDistPoint;

  private String ocspUrl;

  private String policyUrl;

  private boolean basicConstraintsCritical;

  private boolean extendedKeyUsageCritical;

  private String provider;

  private KeySizeType keySize;

  private Set<KeyUsageType> keyUsage;

  private Set<ExtendedKeyUsageType> extendedKeyUsage;

  private Set<SubjectAlternativeName> alternativeNames;

  private Map<String, String> certificatePolicies;

  private List<CertificateExtension> extensions;

  public CertificateParameters(final DistinguishedName subject) {
    this(subject, null);
  }

  public CertificateParameters(final DistinguishedName subject, final Identity issuer) {
    super();
    this.subject = subject;
    this.issuer = issuer;
    this.keyUsage = new HashSet<>();
    this.extendedKeyUsage = new HashSet<>();
    this.alternativeNames = new HashSet<>();
    this.certificatePolicies = new HashMap<>();
    this.extensions = new ArrayList<>();
  }

  public DistinguishedName getSubject() {
    return this.subject;
  }

  public void setSubject(final DistinguishedName subject) {
    this.subject = subject;
  }

  public KeyPair getKeyPair() {
    return this.keyPair;
  }

  public void setKeyPair(final KeyPair keyPair) {
    this.keyPair = keyPair;
  }

  public KeyPairType getKeyPairType() {
    return this.keyPairType;
  }

  public void setKeyPairType(final KeyPairType keyPairType) {
    this.keyPairType = keyPairType;
  }

  public SignatureType getSignatureType() {
    return this.signatureType;
  }

  public void setSignatureType(final SignatureType signatureType) {
    this.signatureType = signatureType;
  }

  public Identity getIssuer() {
    return this.issuer;
  }

  public void setIssuer(final Identity issuer) {
    this.issuer = issuer;
  }

  public BigInteger getSerialNumber() {
    return this.serialNumber;
  }

  public void setSerialNumber(final BigInteger serialNumber) {
    this.serialNumber = serialNumber;
  }

  public Date getNotBefore() {
    return this.notBefore;
  }

  public void setNotBefore(final Date notBefore) {
    this.notBefore = notBefore;
  }

  public Date getNotAfter() {
    return this.notAfter;
  }

  public void setNotAfter(final Date notAfter) {
    this.notAfter = notAfter;
  }

  public String getComment() {
    return this.comment;
  }

  public void setComment(final String comment) {
    this.comment = comment;
  }

  public String getCrlDistPoint() {
    return this.crlDistPoint;
  }

  public void setCrlDistPoint(final String crlDistPoint) {
    this.crlDistPoint = crlDistPoint;
  }

  public String getOcspUrl() {
    return this.ocspUrl;
  }

  public void setOcspUrl(final String ocspUrl) {
    this.ocspUrl = ocspUrl;
  }

  public String getPolicyUrl() {
    return this.policyUrl;
  }

  public void setPolicyUrl(final String policyUrl) {
    this.policyUrl = policyUrl;
  }

  public boolean isBasicConstraintsCritical() {
    return this.basicConstraintsCritical;
  }

  public void setBasicConstraintsCritical(final boolean basicConstraintsCritical) {
    this.basicConstraintsCritical = basicConstraintsCritical;
  }

  public boolean isExtendedKeyUsageCritical() {
    return this.extendedKeyUsageCritical;
  }

  public void setExtendedKeyUsageCritical(final boolean extendedKeyUsageCritical) {
    this.extendedKeyUsageCritical = extendedKeyUsageCritical;
  }

  public String getProvider() {
    return this.provider;
  }

  public void setProvider(final String provider) {
    this.provider = provider;
  }

  public KeySizeType getKeySize() {
    return this.keySize;
  }

  public void setKeySize(final KeySizeType keySize) {
    this.keySize = keySize;
  }

  public Set<KeyUsageType> getKeyUsage() {
    return this.keyUsage;
  }

  public void setKeyUsage(final Set<KeyUsageType> keyUsage) {
    this.keyUsage = keyUsage;
  }

  public Set<ExtendedKeyUsageType> getExtendedKeyUsage() {
    return this.extendedKeyUsage;
  }

  public void setExtendedKeyUsage(final Set<ExtendedKeyUsageType> extendedKeyUsage) {
    this.extendedKeyUsage = extendedKeyUsage;
  }

  public Set<SubjectAlternativeName> getAlternativeNames() {
    return this.alternativeNames;
  }

  public void setAlternativeNames(final Set<SubjectAlternativeName> alternativeNames) {
    this.alternativeNames = alternativeNames;
  }

  public Map<String, String> getCertificatePolicies() {
    return this.certificatePolicies;
  }

  public void setCertificatePolicies(final Map<String, String> certificatePolicies) {
    this.certificatePolicies = certificatePolicies;
  }

  public List<CertificateExtension> getExtensions() {
    return this.extensions;
  }

  public void setExtensions(final List<CertificateExtension> extensions) {
    this.extensions = extensions;
  }

}
