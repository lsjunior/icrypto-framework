package com.github.lsjunior.icrypto.api.model;

import java.io.Serializable;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.util.List;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.google.common.io.ByteSource;

public class Document implements Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private List<Certificate> certificates;

  private List<CRL> crls;

  private List<Signature> signatures;

  private ByteSource content;

  private List<ErrorMessage> errors;

  public Document() {
    super();
  }

  public List<Certificate> getCertificates() {
    return this.certificates;
  }

  public void setCertificates(final List<Certificate> certificates) {
    this.certificates = certificates;
  }

  public List<CRL> getCrls() {
    return this.crls;
  }

  public void setCrls(final List<CRL> crls) {
    this.crls = crls;
  }

  public List<Signature> getSignatures() {
    return this.signatures;
  }

  public void setSignatures(final List<Signature> signatures) {
    this.signatures = signatures;
  }

  public ByteSource getContent() {
    return this.content;
  }

  public void setContent(final ByteSource content) {
    this.content = content;
  }

  public List<ErrorMessage> getErrors() {
    return this.errors;
  }

  public void setErrors(final List<ErrorMessage> errors) {
    this.errors = errors;
  }

}
