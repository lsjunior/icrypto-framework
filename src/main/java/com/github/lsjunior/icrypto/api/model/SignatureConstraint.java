package com.github.lsjunior.icrypto.api.model;

import java.io.Serializable;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.api.type.SignatureType;

public class SignatureConstraint implements Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private SignatureType signatureType;

  private int minKeySize;

  public SignatureConstraint() {
    super();
  }

  public SignatureConstraint(final SignatureType signatureType, final int minKeySize) {
    super();
    this.signatureType = signatureType;
    this.minKeySize = minKeySize;
  }

  public SignatureType getSignatureType() {
    return this.signatureType;
  }

  public void setSignatureType(final SignatureType signatureType) {
    this.signatureType = signatureType;
  }

  public int getMinKeySize() {
    return this.minKeySize;
  }

  public void setMinKeySize(final int minKeySize) {
    this.minKeySize = minKeySize;
  }

  @Override
  public String toString() {
    return this.getSignatureType() + "[" + this.getMinKeySize() + "]";
  }

}
