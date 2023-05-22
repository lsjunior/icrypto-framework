package com.github.lsjunior.icrypto.core.signature.cms;

import java.io.Serializable;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.api.model.Document;

public class CadesVerificationResult implements Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private Document document;

  private boolean valid;

  public CadesVerificationResult() {
    super();
  }

  public Document getDocument() {
    return this.document;
  }

  public void setDocument(final Document document) {
    this.document = document;
  }

  public boolean isValid() {
    return this.valid;
  }

  public void setValid(final boolean valid) {
    this.valid = valid;
  }

}
