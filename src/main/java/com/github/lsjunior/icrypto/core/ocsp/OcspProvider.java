package com.github.lsjunior.icrypto.core.ocsp;

import java.security.cert.Certificate;

public interface OcspProvider {

  byte[] getOcsp(Certificate certificate, Certificate issuer);

}
