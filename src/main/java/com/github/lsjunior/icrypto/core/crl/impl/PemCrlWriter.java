package com.github.lsjunior.icrypto.core.crl.impl;

import java.io.Serializable;
import java.security.cert.CRL;
import java.security.cert.X509CRL;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.core.crl.CrlWriter;
import com.github.lsjunior.icrypto.core.util.AbstractPemWriter;
import com.github.lsjunior.icrypto.core.util.PemTypes;

public class PemCrlWriter extends AbstractPemWriter<CRL> implements CrlWriter, Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private static final PemCrlWriter INSTANCE = new PemCrlWriter();

  private PemCrlWriter() {
    super(PemTypes.CRL);
  }

  @Override
  protected byte[] toByteArray(CRL t) throws Exception {
    X509CRL x509crl = (X509CRL) t;
    return x509crl.getEncoded();
  }

  public static PemCrlWriter getInstance() {
    return PemCrlWriter.INSTANCE;
  }

}
