package com.github.lsjunior.icrypto.api.model;

import java.io.Serializable;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.List;
import java.util.Map;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.api.type.SignatureType;
import com.google.common.io.ByteSource;

public class Signature implements Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private CertificateId certificateId;

  private String contentType;

  private String contentHints;

  private Date signingTime;

  private String commitmentType;

  private ByteSource encoded;

  private ByteSource signature;

  private String messageDigest;

  private LocationName signerLocation;

  private TimeStamp contentTimeStamp;

  private TimeStamp signatureTimeStamp;

  private TimeStamp referenceTimeStamp;

  private TimeStamp archiveTimeStamp;

  private SignaturePolicy signaturePolicy;

  private SignatureType signatureType;

  private List<Certificate> chain;

  private Map<String, byte[]> signedAttributes;

  private Map<String, byte[]> unsignedAttributes;

  private List<ErrorMessage> errors;

  // PDF
  private String filter;

  private String subFilter;

  public Signature() {
    super();
  }

  public CertificateId getCertificateId() {
    return this.certificateId;
  }

  public void setCertificateId(final CertificateId certificateId) {
    this.certificateId = certificateId;
  }

  public String getContentType() {
    return this.contentType;
  }

  public void setContentType(final String contentType) {
    this.contentType = contentType;
  }

  public String getContentHints() {
    return this.contentHints;
  }

  public void setContentHints(final String contentHints) {
    this.contentHints = contentHints;
  }

  public Date getSigningTime() {
    return this.signingTime;
  }

  public void setSigningTime(final Date signingTime) {
    this.signingTime = signingTime;
  }

  public String getCommitmentType() {
    return this.commitmentType;
  }

  public void setCommitmentType(final String commitmentType) {
    this.commitmentType = commitmentType;
  }

  public ByteSource getEncoded() {
    return this.encoded;
  }

  public void setEncoded(final ByteSource encoded) {
    this.encoded = encoded;
  }

  public ByteSource getSignature() {
    return this.signature;
  }

  public void setSignature(final ByteSource signature) {
    this.signature = signature;
  }

  public String getMessageDigest() {
    return this.messageDigest;
  }

  public void setMessageDigest(final String messageDigest) {
    this.messageDigest = messageDigest;
  }

  public LocationName getSignerLocation() {
    return this.signerLocation;
  }

  public void setSignerLocation(final LocationName signerLocation) {
    this.signerLocation = signerLocation;
  }

  public TimeStamp getContentTimeStamp() {
    return this.contentTimeStamp;
  }

  public void setContentTimeStamp(final TimeStamp contentTimeStamp) {
    this.contentTimeStamp = contentTimeStamp;
  }

  public TimeStamp getSignatureTimeStamp() {
    return this.signatureTimeStamp;
  }

  public void setSignatureTimeStamp(final TimeStamp signatureTimeStamp) {
    this.signatureTimeStamp = signatureTimeStamp;
  }

  public TimeStamp getReferenceTimeStamp() {
    return this.referenceTimeStamp;
  }

  public void setReferenceTimeStamp(final TimeStamp referenceTimeStamp) {
    this.referenceTimeStamp = referenceTimeStamp;
  }

  public TimeStamp getArchiveTimeStamp() {
    return this.archiveTimeStamp;
  }

  public void setArchiveTimeStamp(final TimeStamp archiveTimeStamp) {
    this.archiveTimeStamp = archiveTimeStamp;
  }

  public SignaturePolicy getSignaturePolicy() {
    return this.signaturePolicy;
  }

  public void setSignaturePolicy(final SignaturePolicy signaturePolicy) {
    this.signaturePolicy = signaturePolicy;
  }

  public SignatureType getSignatureType() {
    return this.signatureType;
  }

  public void setSignatureType(final SignatureType signatureType) {
    this.signatureType = signatureType;
  }

  public List<Certificate> getChain() {
    return this.chain;
  }

  public void setChain(final List<Certificate> chain) {
    this.chain = chain;
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

  public List<ErrorMessage> getErrors() {
    return this.errors;
  }

  public void setErrors(final List<ErrorMessage> errors) {
    this.errors = errors;
  }

  public String getFilter() {
    return this.filter;
  }

  public void setFilter(final String filter) {
    this.filter = filter;
  }

  public String getSubFilter() {
    return this.subFilter;
  }

  public void setSubFilter(final String subFilter) {
    this.subFilter = subFilter;
  }

  // Aux
  public boolean isValid() {
    return !this.errors.stream().anyMatch((e) -> e.isFatal());
  }

}
