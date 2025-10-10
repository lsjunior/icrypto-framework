package com.github.lsjunior.icrypto.core.crl.impl;

import java.security.cert.Certificate;
import java.security.cert.X509CRL;

import com.github.lsjunior.icrypto.ICryptoException;
import com.github.lsjunior.icrypto.core.crl.CrlProvider;
import com.github.lsjunior.icrypto.core.crl.util.Crls;

public class DefaultCrlProvider implements CrlProvider {

  public DefaultCrlProvider() {
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
