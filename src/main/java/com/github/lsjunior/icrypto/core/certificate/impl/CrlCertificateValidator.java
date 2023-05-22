package com.github.lsjunior.icrypto.core.certificate.impl;

import java.io.Serializable;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.ICryptoException;
import com.github.lsjunior.icrypto.core.certificate.CertificateValidator;
import com.github.lsjunior.icrypto.core.certificate.ValidationError;
import com.github.lsjunior.icrypto.core.crl.CrlProvider;
import com.github.lsjunior.icrypto.core.crl.impl.SimpleCrlProvider;
import com.github.lsjunior.icrypto.core.crl.util.Crls;

public class CrlCertificateValidator implements CertificateValidator, Serializable {

  public static final String VALIDATOR_NAME = "CRL Validator";

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private final CrlProvider crlProvider;

  public CrlCertificateValidator() {
    this(new SimpleCrlProvider());
  }

  public CrlCertificateValidator(final CrlProvider crlProvider) {
    super();
    this.crlProvider = crlProvider;
  }

  @Override
  public Collection<ValidationError> validate(final List<Certificate> chain) {
    try {
      X509Certificate certificate = (X509Certificate) chain.get(0);
      byte[] bytes = this.crlProvider.getCrl(certificate);
      if (bytes == null) {
        return Collections.singleton(new ValidationError(CrlCertificateValidator.VALIDATOR_NAME, "No URL found for validation"));
      }

      X509CRL x509crl = (X509CRL) Crls.toCrl(bytes);
      if (x509crl.isRevoked(certificate)) {
        return Collections.singleton(new ValidationError(CrlCertificateValidator.VALIDATOR_NAME, "Certificate revoked"));
      }

      if (x509crl.getRevokedCertificate(certificate.getSerialNumber()) != null) {
        return Collections.singleton(new ValidationError(CrlCertificateValidator.VALIDATOR_NAME, "Certificate revoked"));
      }

      return Collections.emptyList();
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }
}
