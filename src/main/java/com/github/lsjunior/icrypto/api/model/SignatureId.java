package com.github.lsjunior.icrypto.api.model;

import java.io.Serializable;
import java.security.cert.Certificate;

import com.github.lsjunior.icrypto.ICryptoConstants;

public class SignatureId implements Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private int index;

  private Certificate certificate;

  private DistinguishedName distinguishedName;

  public SignatureId(final int index) {
    super();
    this.index = index;
  }

  public SignatureId(final Certificate certificate) {
    super();
    this.certificate = certificate;
  }

  public SignatureId(final DistinguishedName distinguishedName) {
    super();
    this.distinguishedName = distinguishedName;
  }

  public int getIndex() {
    return this.index;
  }

  public Certificate getCertificate() {
    return this.certificate;
  }

  public DistinguishedName getDistinguishedName() {
    return this.distinguishedName;
  }

}
