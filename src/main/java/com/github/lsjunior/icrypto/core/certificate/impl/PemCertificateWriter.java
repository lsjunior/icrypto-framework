package com.github.lsjunior.icrypto.core.certificate.impl;

import java.io.Serializable;
import java.security.cert.Certificate;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.core.certificate.CertificateWriter;
import com.github.lsjunior.icrypto.core.util.AbstractPemWriter;
import com.github.lsjunior.icrypto.core.util.PemTypes;

public class PemCertificateWriter extends AbstractPemWriter<Certificate> implements CertificateWriter, Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private static final PemCertificateWriter INSTANCE = new PemCertificateWriter();

  private PemCertificateWriter() {
    super(PemTypes.CERTIFICATE);
  }

  @Override
  protected byte[] toByteArray(Certificate t) throws Exception {
    return t.getEncoded();
  }

  public static PemCertificateWriter getInstance() {
    return PemCertificateWriter.INSTANCE;
  }

}
