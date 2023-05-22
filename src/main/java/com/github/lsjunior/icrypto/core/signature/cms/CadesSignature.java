package com.github.lsjunior.icrypto.core.signature.cms;

import java.io.Serializable;
import java.security.cert.Certificate;
import java.util.List;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.google.common.io.ByteSource;

public class CadesSignature implements Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private String algorithm;

  private Certificate certificate;

  private List<Certificate> chain;

  private ByteSource data;

  public CadesSignature() {
    super();
  }

  public String getAlgorithm() {
    return this.algorithm;
  }

  public void setAlgorithm(final String algorithm) {
    this.algorithm = algorithm;
  }

  public Certificate getCertificate() {
    return this.certificate;
  }

  public void setCertificate(final Certificate certificate) {
    this.certificate = certificate;
  }

  public List<Certificate> getChain() {
    return this.chain;
  }

  public void setChain(final List<Certificate> chain) {
    this.chain = chain;
  }

  public ByteSource getData() {
    return this.data;
  }

  public void setData(final ByteSource data) {
    this.data = data;
  }

}
