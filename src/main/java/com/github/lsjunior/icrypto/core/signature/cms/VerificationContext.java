package com.github.lsjunior.icrypto.core.signature.cms;

import java.io.Serializable;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.api.model.Document;
import com.github.lsjunior.icrypto.api.model.Signature;
import com.github.lsjunior.icrypto.core.certificate.CertPathProvider;

public class VerificationContext implements Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private Document document;

  private Signature signature;

  private CertPathProvider certPathProvider;

  public VerificationContext() {
    super();
  }

  public Document getDocument() {
    return this.document;
  }

  public void setDocument(final Document document) {
    this.document = document;
  }

  public Signature getSignature() {
    return this.signature;
  }

  public void setSignature(final Signature signature) {
    this.signature = signature;
  }

  public CertPathProvider getCertPathProvider() {
    return this.certPathProvider;
  }

  public void setCertPathProvider(final CertPathProvider certPathProvider) {
    this.certPathProvider = certPathProvider;
  }

}
