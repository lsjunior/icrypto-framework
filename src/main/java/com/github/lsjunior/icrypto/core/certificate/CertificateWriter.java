package com.github.lsjunior.icrypto.core.certificate;

import java.io.OutputStream;
import java.security.cert.Certificate;
import java.util.List;

public interface CertificateWriter {

  void write(List<Certificate> chain, OutputStream outputStream);

}
