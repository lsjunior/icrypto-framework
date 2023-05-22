package com.github.lsjunior.icrypto.api.model;

import java.io.Serializable;
import java.math.BigInteger;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.api.type.DigestType;

public class CertificateId implements Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private BigInteger serial;

  private String issuer;

  private byte[] digest;

  private DigestType digestType;

  public CertificateId() {
    super();
  }

  public CertificateId(final BigInteger serial, final String issuer, final byte[] digest, final DigestType digestType) {
    super();
    this.serial = serial;
    this.issuer = issuer;
    this.digest = digest;
    this.digestType = digestType;
  }

  public BigInteger getSerial() {
    return this.serial;
  }

  public void setSerial(final BigInteger serial) {
    this.serial = serial;
  }

  public String getIssuer() {
    return this.issuer;
  }

  public void setIssuer(final String issuer) {
    this.issuer = issuer;
  }

  public byte[] getDigest() {
    return this.digest;
  }

  public void setDigest(final byte[] digest) {
    this.digest = digest;
  }

  public DigestType getDigestType() {
    return this.digestType;
  }

  public void setDigestType(final DigestType digestType) {
    this.digestType = digestType;
  }

}
