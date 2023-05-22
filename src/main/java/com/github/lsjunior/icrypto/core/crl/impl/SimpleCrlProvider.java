package com.github.lsjunior.icrypto.core.crl.impl;

import java.io.Serializable;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.ICryptoException;
import com.github.lsjunior.icrypto.core.crl.CrlProvider;
import com.github.lsjunior.icrypto.core.crl.util.Crls;

public class SimpleCrlProvider implements CrlProvider, Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  public SimpleCrlProvider() {
    super();
  }

  @Override
  public byte[] getCrl(final Certificate certificate) {
    try {
      X509CRL crl = (X509CRL) Crls.getCrl(certificate);
      if (crl != null) {
        return crl.getEncoded();
      }
      return null;
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }

}
