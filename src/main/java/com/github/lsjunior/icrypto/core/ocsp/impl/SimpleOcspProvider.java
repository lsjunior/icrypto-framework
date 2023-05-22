package com.github.lsjunior.icrypto.core.ocsp.impl;

import java.io.Serializable;
import java.security.cert.Certificate;

import org.bouncycastle.cert.ocsp.OCSPResp;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.ICryptoException;
import com.github.lsjunior.icrypto.core.ocsp.OcspProvider;
import com.github.lsjunior.icrypto.core.ocsp.util.Ocsps;

public class SimpleOcspProvider implements OcspProvider, Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  public SimpleOcspProvider() {
    super();
  }

  @Override
  public byte[] getOcsp(final Certificate certificate, final Certificate issuer) {
    try {
      OCSPResp resp = Ocsps.getOcsp(certificate, issuer);
      if (resp != null) {
        return resp.getEncoded();
      }
      return null;
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }

}
