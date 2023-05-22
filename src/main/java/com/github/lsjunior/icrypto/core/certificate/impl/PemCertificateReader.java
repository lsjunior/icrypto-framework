package com.github.lsjunior.icrypto.core.certificate.impl;

import java.io.Serializable;
import java.security.cert.Certificate;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.core.certificate.CertificateReader;
import com.github.lsjunior.icrypto.core.certificate.util.Certificates;
import com.github.lsjunior.icrypto.core.util.AbstractPemReader;
import com.github.lsjunior.icrypto.core.util.PemTypes;

public class PemCertificateReader extends AbstractPemReader<Certificate> implements CertificateReader, Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private static final PemCertificateReader INSTANCE = new PemCertificateReader();

  private PemCertificateReader() {
    super(PemTypes.CERTIFICATE);
  }

  @Override
  protected Certificate toObject(byte[] bytes) throws Exception {
    return Certificates.toCertificate(bytes);
  }

  public static PemCertificateReader getInstance() {
    return PemCertificateReader.INSTANCE;
  }

}
