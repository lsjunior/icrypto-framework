package com.github.lsjunior.icrypto.core.certificate.impl;

import java.io.InputStream;
import java.io.Serializable;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.List;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.ICryptoException;
import com.github.lsjunior.icrypto.core.certificate.CertificateReader;
import com.github.lsjunior.icrypto.core.certificate.util.Certificates;

public class DerCertificateReader implements CertificateReader, Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  public DerCertificateReader() {
    super();
  }

  @Override
  public List<Certificate> read(final InputStream inputStream) {
    try {
      Certificate certificate = Certificates.toCertificate(inputStream);
      return Collections.singletonList(certificate);
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }

}
