package com.github.lsjunior.icrypto.core.crl;

import java.io.OutputStream;
import java.security.cert.CRL;
import java.util.List;

public interface CrlWriter {

  void write(List<CRL> crls, OutputStream outputStream);

}
