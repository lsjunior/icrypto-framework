package com.github.lsjunior.icrypto.core.certificate.impl;

import java.io.OutputStream;
import java.io.Serializable;
import java.security.cert.Certificate;
import java.util.List;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.ICryptoException;
import com.github.lsjunior.icrypto.core.certificate.CertificateWriter;

public class DerCertificateWriter implements CertificateWriter, Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  public DerCertificateWriter() {
    super();
  }

  @Override
  public void write(final List<Certificate> chain, final OutputStream outputStream) {
    try {
      outputStream.write(chain.get(0).getEncoded());
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }

}
