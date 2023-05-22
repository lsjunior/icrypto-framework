package com.github.lsjunior.icrypto.core.crl;

import java.security.cert.Certificate;

public interface CrlProvider {

  byte[] getCrl(Certificate certificate);

}
