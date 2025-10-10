package com.github.lsjunior.icrypto.core.ocsp.impl;

import java.security.cert.Certificate;

import org.bouncycastle.cert.ocsp.OCSPResp;

import com.github.lsjunior.icrypto.ICryptoException;
import com.github.lsjunior.icrypto.core.ocsp.OcspProvider;
import com.github.lsjunior.icrypto.core.ocsp.util.Ocsps;

public class DefaultOcspProvider implements OcspProvider {

  public DefaultOcspProvider() {
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
