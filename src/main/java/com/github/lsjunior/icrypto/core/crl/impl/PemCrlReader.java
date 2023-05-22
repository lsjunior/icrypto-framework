package com.github.lsjunior.icrypto.core.crl.impl;

import java.io.Serializable;
import java.security.cert.CRL;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.core.crl.CrlReader;
import com.github.lsjunior.icrypto.core.crl.util.Crls;
import com.github.lsjunior.icrypto.core.util.AbstractPemReader;
import com.github.lsjunior.icrypto.core.util.PemTypes;

public class PemCrlReader extends AbstractPemReader<CRL> implements CrlReader, Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private static final PemCrlReader INSTANCE = new PemCrlReader();

  private PemCrlReader() {
    super(PemTypes.CRL);
  }

  @Override
  protected CRL toObject(byte[] bytes) throws Exception {
    return Crls.toCrl(bytes);
  }

  public static PemCrlReader getInstance() {
    return PemCrlReader.INSTANCE;
  }
}
