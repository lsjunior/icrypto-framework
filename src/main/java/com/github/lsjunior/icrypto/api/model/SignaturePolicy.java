package com.github.lsjunior.icrypto.api.model;

import java.io.Serializable;
import java.util.Date;
import java.util.Set;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.api.type.DigestType;

public class SignaturePolicy implements Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private String policyId;

  private String policyName;

  private String policyUrl;

  private DigestType digestType;

  private byte[] digestValue;

  private Date notBefore;

  private Date notAfter;

  private boolean detached;

  private boolean valid;

  private SignatureVersion signatureVersion;

  private Set<SignatureConstraint> signatureConstraints;

  private Set<String> requiredSignedAttributes;

  private Set<String> requiredUnsignedAttributes;

  private byte[] encoded;

  public SignaturePolicy() {
    super();
  }

  public String getPolicyId() {
    return this.policyId;
  }

  public void setPolicyId(final String policyId) {
    this.policyId = policyId;
  }

  public String getPolicyName() {
    return this.policyName;
  }

  public void setPolicyName(final String policyName) {
    this.policyName = policyName;
  }

  public String getPolicyUrl() {
    return this.policyUrl;
  }

  public void setPolicyUrl(final String policyUrl) {
    this.policyUrl = policyUrl;
  }

  public DigestType getDigestType() {
    return this.digestType;
  }

  public void setDigestType(final DigestType digestType) {
    this.digestType = digestType;
  }

  public byte[] getDigestValue() {
    return this.digestValue;
  }

  public void setDigestValue(final byte[] digestValue) {
    this.digestValue = digestValue;
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

  public boolean isDetached() {
    return this.detached;
  }

  public void setDetached(final boolean detached) {
    this.detached = detached;
  }

  public boolean isValid() {
    return this.valid;
  }

  public void setValid(final boolean valid) {
    this.valid = valid;
  }

  public SignatureVersion getSignatureVersion() {
    return this.signatureVersion;
  }

  public void setSignatureVersion(final SignatureVersion signatureVersion) {
    this.signatureVersion = signatureVersion;
  }

  public Set<SignatureConstraint> getSignatureConstraints() {
    return this.signatureConstraints;
  }

  public void setSignatureConstraints(final Set<SignatureConstraint> signatureConstraints) {
    this.signatureConstraints = signatureConstraints;
  }

  public Set<String> getRequiredSignedAttributes() {
    return this.requiredSignedAttributes;
  }

  public void setRequiredSignedAttributes(final Set<String> requiredSignedAttributes) {
    this.requiredSignedAttributes = requiredSignedAttributes;
  }

  public Set<String> getRequiredUnsignedAttributes() {
    return this.requiredUnsignedAttributes;
  }

  public void setRequiredUnsignedAttributes(final Set<String> requiredUnsignedAttributes) {
    this.requiredUnsignedAttributes = requiredUnsignedAttributes;
  }

  public byte[] getEncoded() {
    return this.encoded;
  }

  public void setEncoded(final byte[] encoded) {
    this.encoded = encoded;
  }

  // Object
  @Override
  public String toString() {
    return this.getPolicyId();
  }
}
