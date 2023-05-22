package com.github.lsjunior.icrypto.core.signature.cms;

import java.io.File;
import java.io.Serializable;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.List;
import java.util.Map;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.api.model.CertificateRevocationData;
import com.github.lsjunior.icrypto.api.model.LocationName;
import com.github.lsjunior.icrypto.api.model.SignatureId;
import com.github.lsjunior.icrypto.api.model.SignaturePolicy;
import com.github.lsjunior.icrypto.api.model.TimeStamp;
import com.github.lsjunior.icrypto.api.type.SignatureType;
import com.github.lsjunior.icrypto.core.certificate.CertPathProvider;
import com.github.lsjunior.icrypto.core.crl.CrlProvider;
import com.github.lsjunior.icrypto.core.ocsp.OcspProvider;
import com.github.lsjunior.icrypto.core.timestamp.TimeStampProvider;

public class CadesSignatureContext implements Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private String signerId;

  private PrivateKey privateKey;

  private List<Certificate> chain;

  private SignatureType signatureType;

  private SignaturePolicy policy;

  private File data;

  private File signedData;

  private boolean dataDigested;

  private boolean detached;

  private boolean ignoreSigningTime;

  private Date date;

  private String contentName;

  private String contentType;

  private TimeStamp contentTimeStamp;

  private Boolean validatePolicy;

  private Boolean validateCertificate;

  private String commitmentType;

  private TimeStampProvider timeStampClient;

  private LocationName locationName;

  private CertPathProvider certPathProvider;

  private CrlProvider crlProvider;

  private OcspProvider ocspProvider;

  private SignatureProfile profile;

  private SignatureId signatureId;

  private String signatureProvider;

  private String digestProvider;

  private Map<String, byte[]> signedAttributes;

  private Map<String, byte[]> unsignedAttributes;

  private Map<Certificate, CertificateRevocationData> revocations;

  public CadesSignatureContext() {
    super();
  }

  public String getSignerId() {
    return this.signerId;
  }

  public void setSignerId(final String signerId) {
    this.signerId = signerId;
  }

  public PrivateKey getPrivateKey() {
    return this.privateKey;
  }

  public void setPrivateKey(final PrivateKey privateKey) {
    this.privateKey = privateKey;
  }

  public List<Certificate> getChain() {
    return this.chain;
  }

  public void setChain(final List<Certificate> chain) {
    this.chain = chain;
  }

  public SignatureType getSignatureType() {
    return this.signatureType;
  }

  public void setSignatureType(final SignatureType signatureType) {
    this.signatureType = signatureType;
  }

  public SignaturePolicy getPolicy() {
    return this.policy;
  }

  public void setPolicy(final SignaturePolicy policy) {
    this.policy = policy;
  }

  public File getData() {
    return this.data;
  }

  public void setData(final File data) {
    this.data = data;
  }

  public File getSignedData() {
    return this.signedData;
  }

  public void setSignedData(final File signedData) {
    this.signedData = signedData;
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

  public String getContentName() {
    return this.contentName;
  }

  public void setContentName(final String contentName) {
    this.contentName = contentName;
  }

  public String getContentType() {
    return this.contentType;
  }

  public void setContentType(final String contentType) {
    this.contentType = contentType;
  }

  public TimeStamp getContentTimeStamp() {
    return this.contentTimeStamp;
  }

  public void setContentTimeStamp(final TimeStamp contentTimeStamp) {
    this.contentTimeStamp = contentTimeStamp;
  }

  public Boolean getValidatePolicy() {
    return this.validatePolicy;
  }

  public void setValidatePolicy(final Boolean validatePolicy) {
    this.validatePolicy = validatePolicy;
  }

  public Boolean getValidateCertificate() {
    return this.validateCertificate;
  }

  public void setValidateCertificate(final Boolean validateCertificate) {
    this.validateCertificate = validateCertificate;
  }

  public String getCommitmentType() {
    return this.commitmentType;
  }

  public void setCommitmentType(final String commitmentType) {
    this.commitmentType = commitmentType;
  }

  public TimeStampProvider getTimeStampClient() {
    return this.timeStampClient;
  }

  public void setTimeStampClient(final TimeStampProvider timeStampClient) {
    this.timeStampClient = timeStampClient;
  }

  public LocationName getLocationName() {
    return this.locationName;
  }

  public void setLocationName(final LocationName locationName) {
    this.locationName = locationName;
  }

  public CertPathProvider getCertPathProvider() {
    return this.certPathProvider;
  }

  public void setCertPathProvider(final CertPathProvider certPathProvider) {
    this.certPathProvider = certPathProvider;
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

  public SignatureProfile getProfile() {
    return this.profile;
  }

  public void setProfile(final SignatureProfile profile) {
    this.profile = profile;
  }

  public SignatureId getSignatureId() {
    return this.signatureId;
  }

  public void setSignatureId(final SignatureId signatureId) {
    this.signatureId = signatureId;
  }

  public String getSignatureProvider() {
    return this.signatureProvider;
  }

  public void setSignatureProvider(final String signatureProvider) {
    this.signatureProvider = signatureProvider;
  }

  public String getDigestProvider() {
    return this.digestProvider;
  }

  public void setDigestProvider(final String digestProvider) {
    this.digestProvider = digestProvider;
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

  // Aux
  public String getAlgorithm() {
    return this.getSignatureType().getAlgorithm();
  }

}
