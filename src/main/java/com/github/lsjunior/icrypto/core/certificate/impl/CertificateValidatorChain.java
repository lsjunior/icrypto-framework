package com.github.lsjunior.icrypto.core.certificate.impl;

import java.io.Serializable;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.core.certificate.CertificateValidator;
import com.github.lsjunior.icrypto.core.certificate.ValidationError;

public class CertificateValidatorChain implements CertificateValidator, Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private final List<CertificateValidator> chain;

  public CertificateValidatorChain() {
    super();
    this.chain = new ArrayList<>();
  }

  public CertificateValidatorChain(final List<CertificateValidator> chain) {
    super();
    this.chain = chain;
  }

  public void add(final CertificateValidator validator) {
    this.chain.add(validator);
  }

  @Override
  public Collection<ValidationError> validate(final List<Certificate> chain) {
    List<ValidationError> list = new ArrayList<>();
    for (CertificateValidator validator : this.chain) {
      if (validator != null) {
        Collection<ValidationError> errors = validator.validate(chain);
        list.addAll(errors);
      }
    }
    return list;
  }

}
