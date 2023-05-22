package com.github.lsjunior.icrypto.core.certificate;

public interface CsrService {

  CertificateParameters parse(byte[] csr);

  byte[] generate(CertificateParameters request);

}
