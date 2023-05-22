package com.github.lsjunior.icrypto.core.signature.cms;

import java.io.Serializable;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.Map;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.api.model.CertificateRevocationData;
import com.github.lsjunior.icrypto.api.model.LocationName;
import com.github.lsjunior.icrypto.api.model.SignatureId;
import com.github.lsjunior.icrypto.api.model.SignaturePolicy;
import com.github.lsjunior.icrypto.api.model.TimeStamp;
import com.github.lsjunior.icrypto.core.Identity;
import com.github.lsjunior.icrypto.core.certificate.CertPathProvider;
import com.github.lsjunior.icrypto.core.crl.CrlProvider;
import com.github.lsjunior.icrypto.core.ocsp.OcspProvider;
import com.github.lsjunior.icrypto.core.timestamp.TimeStampProvider;
import com.google.common.io.ByteSource;

public class CadesSignatureParameters implements Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private String algorithm;

  private CertPathProvider certPathProvider;

  private String commitmentType;

  private String contentName;

  private TimeStamp contentTimeStamp;

  private String contentType;

  private CrlProvider crlProvider;

  private OcspProvider ocspProvider;

  private ByteSource data;

  private boolean dataDigested;

  private boolean detached;

  private boolean validateCertificate;

  private boolean ignoreSigningTime;

  private Date date;

  private String digestProvider;

  private Identity identity;

  private LocationName location;

  private String provider;

  private SignatureProfile signatureProfile;

  private SignatureId signatureId;

  private SignaturePolicy signaturePolicy;

  private String signatureProvider;

  private TimeStampProvider timeStampProvider;

  private Map<String, byte[]> signedAttributes;

  private Map<String, byte[]> unsignedAttributes;

  private Map<Certificate, CertificateRevocationData> revocations;

  public CadesSignatureParameters() {
    super();
  }

  public String getAlgorithm() {
    return this.algorithm;
  }

  public void setAlgorithm(final String algorithm) {
    this.algorithm = algorithm;
  }

  public CertPathProvider getCertPathProvider() {
    return this.certPathProvider;
  }

  public void setCertPathProvider(final CertPathProvider certPathProvider) {
    this.certPathProvider = certPathProvider;
  }

  public String getCommitmentType() {
    return this.commitmentType;
  }

  public void setCommitmentType(final String commitmentType) {
    this.commitmentType = commitmentType;
  }

  public String getContentName() {
    return this.contentName;
  }

  public void setContentName(final String contentName) {
    this.contentName = contentName;
  }

  public TimeStamp getContentTimeStamp() {
    return this.contentTimeStamp;
  }

  public void setContentTimeStamp(final TimeStamp contentTimeStamp) {
    this.contentTimeStamp = contentTimeStamp;
  }

  public String getContentType() {
    return this.contentType;
  }

  public void setContentType(final String contentType) {
    this.contentType = contentType;
  }

  public CrlProvider getCrlProvider() {
    return this.crlProvider;
  }

  public void setCrlProvider(final CrlProvider crlProvider) {
    this.crlProvider = crlProvider;
  }

  public OcspProvider getOcspProvider() {
    return this.ocspProvider;
  }

  public void setOcspProvider(final OcspProvider ocspProvider) {
    this.ocspProvider = ocspProvider;
  }

  public ByteSource getData() {
    return this.data;
  }

  public void setData(final ByteSource data) {
    this.data = data;
  }

  public boolean isDataDigested() {
    return this.dataDigested;
  }

  public void setDataDigested(final boolean dataDigested) {
    this.dataDigested = dataDigested;
  }

  public boolean isDetached() {
    return this.detached;
  }

  public void setDetached(final boolean detached) {
    this.detached = detached;
  }

  public boolean isValidateCertificate() {
    return this.validateCertificate;
  }

  public void setValidateCertificate(final boolean validateCertificate) {
    this.validateCertificate = validateCertificate;
  }

  public boolean isIgnoreSigningTime() {
    return this.ignoreSigningTime;
  }

  public void setIgnoreSigningTime(final boolean ignoreSigningTime) {
    this.ignoreSigningTime = ignoreSigningTime;
  }

  public Date getDate() {
    return this.date;
  }

  public void setDate(final Date date) {
    this.date = date;
  }

  public String getDigestProvider() {
    return this.digestProvider;
  }

  public void setDigestProvider(final String digestProvider) {
    this.digestProvider = digestProvider;
  }

  public Identity getIdentity() {
    return this.identity;
  }

  public void setIdentity(final Identity identity) {
    this.identity = identity;
  }

  public LocationName getLocation() {
    return this.location;
  }

  public void setLocation(final LocationName location) {
    this.location = location;
  }

  public String getProvider() {
    return this.provider;
  }

  public void setProvider(final String provider) {
    this.provider = provider;
  }

  public SignatureProfile getSignatureProfile() {
    return this.signatureProfile;
  }

  public void setSignatureProfile(final SignatureProfile signatureProfile) {
    this.signatureProfile = signatureProfile;
  }

  public SignatureId getSignatureId() {
    return this.signatureId;
  }

  public void setSignatureId(final SignatureId signatureId) {
    this.signatureId = signatureId;
  }

  public SignaturePolicy getSignaturePolicy() {
    return this.signaturePolicy;
  }

  public void setSignaturePolicy(final SignaturePolicy signaturePolicy) {
    this.signaturePolicy = signaturePolicy;
  }

  public String getSignatureProvider() {
    return this.signatureProvider;
  }

  public void setSignatureProvider(final String signatureProvider) {
    this.signatureProvider = signatureProvider;
  }

  public TimeStampProvider getTimeStampProvider() {
    return this.timeStampProvider;
  }

  public void setTimeStampProvider(final TimeStampProvider timeStampProvider) {
    this.timeStampProvider = timeStampProvider;
  }

  public Map<String, byte[]> getSignedAttributes() {
    return this.signedAttributes;
  }

  public void setSignedAttributes(final Map<String, byte[]> signedAttributes) {
    this.signedAttributes = signedAttributes;
  }

  public Map<String, byte[]> getUnsignedAttributes() {
    return this.unsignedAttributes;
  }

  public void setUnsignedAttributes(final Map<String, byte[]> unsignedAttributes) {
    this.unsignedAttributes = unsignedAttributes;
  }

  public Map<Certificate, CertificateRevocationData> getRevocations() {
    return this.revocations;
  }

  public void setRevocations(final Map<Certificate, CertificateRevocationData> revocations) {
    this.revocations = revocations;
  }

}
