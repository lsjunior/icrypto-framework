package com.github.lsjunior.icrypto.api.model;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.List;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.api.type.DigestType;
import com.github.lsjunior.icrypto.api.type.SignatureType;

public class TimeStamp implements Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private BigInteger nonce;

  private BigInteger serialNumber;

  private Date date;

  private byte[] encoded;

  private byte[] digest;

  private byte[] content;

  private byte[] signature;

  private String policyId;

  private DigestType digestType;

  private SignatureType signatureType;

  private List<Certificate> chain;

  public TimeStamp() {
    super();
  }

  public BigInteger getNonce() {
    return this.nonce;
  }

  public void setNonce(final BigInteger nonce) {
    this.nonce = nonce;
  }

  public BigInteger getSerialNumber() {
    return this.serialNumber;
  }

  public void setSerialNumber(final BigInteger serialNumber) {
    this.serialNumber = serialNumber;
  }

  public Date getDate() {
    return this.date;
  }

  public void setDate(final Date date) {
    this.date = date;
  }

  public byte[] getEncoded() {
    return this.encoded;
  }

  public void setEncoded(final byte[] encoded) {
    this.encoded = encoded;
  }

  public byte[] getDigest() {
    return this.digest;
  }

  public void setDigest(final byte[] digest) {
    this.digest = digest;
  }

  public byte[] getContent() {
    return this.content;
  }

  public void setContent(final byte[] content) {
    this.content = content;
  }

  public byte[] getSignature() {
    return this.signature;
  }

  public void setSignature(final byte[] signature) {
    this.signature = signature;
  }

  public String getPolicyId() {
    return this.policyId;
  }

  public void setPolicyId(final String policyId) {
    this.policyId = policyId;
  }

  public DigestType getDigestType() {
    return this.digestType;
  }

  public void setDigestType(final DigestType digestType) {
    this.digestType = digestType;
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

}
