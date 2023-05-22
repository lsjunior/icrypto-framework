package com.github.lsjunior.icrypto.api.model;

import java.io.Serializable;
import java.security.cert.CRL;

import com.github.lsjunior.icrypto.ICryptoConstants;

public class CertificateRevocationData implements Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private CRL crl;

  private byte[] ocsp;

  public CertificateRevocationData() {
    super();
  }

  public CRL getCrl() {
    return this.crl;
  }

  public void setCrl(final CRL crl) {
    this.crl = crl;
  }

  public byte[] getOcsp() {
    return this.ocsp;
  }

  public void setOcsp(final byte[] ocsp) {
    this.ocsp = ocsp;
  }

}
