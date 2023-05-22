package com.github.lsjunior.icrypto.core.certificate.impl;

import java.io.Serializable;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.ICryptoException;
import com.github.lsjunior.icrypto.core.certificate.CertificateValidator;
import com.github.lsjunior.icrypto.core.certificate.ValidationError;
import com.github.lsjunior.icrypto.core.certificate.util.Certificates;

public class SelfSignedCertificateValidator implements CertificateValidator, Serializable {

  public static final String VALIDATOR_NAME = "Self Signed Validator";

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  public SelfSignedCertificateValidator() {
    super();
  }

  @Override
  public Collection<ValidationError> validate(final List<Certificate> chain) {
    try {
      Certificate certificate = chain.get(0);
      if (Certificates.isSelfSigned(certificate)) {
        return Collections.singleton(new ValidationError(SelfSignedCertificateValidator.VALIDATOR_NAME, "Certificate self signed"));
      }

      return Collections.emptyList();
    } catch (GeneralSecurityException e) {
      throw new ICryptoException(e);
    }
  }

}
