package com.github.lsjunior.icrypto.core.certificate.impl;

import java.io.Serializable;
import java.security.GeneralSecurityException;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilderException;
import java.security.cert.Certificate;
import java.util.Collection;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.ICryptoException;
import com.github.lsjunior.icrypto.core.certificate.CertPathProvider;
import com.github.lsjunior.icrypto.core.certificate.util.CertPaths;

public class DefaultCertPathProvider implements CertPathProvider, Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private final Collection<Certificate> certificates;

  public DefaultCertPathProvider(final Collection<Certificate> certificates) {
    super();
    this.certificates = certificates;
  }

  @Override
  public CertPath getCertPath(final Certificate certificate) throws CertPathBuilderException {
    if (certificate == null) {
      return null;
    }
    try {
      return CertPaths.toCertPath(certificate, this.certificates);
    } catch (CertPathBuilderException e) {
      throw e;
    } catch (GeneralSecurityException e) {
      throw new ICryptoException(e);
    }
  }

}
