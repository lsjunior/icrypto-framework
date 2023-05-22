package com.github.lsjunior.icrypto.core.crl;

import java.io.InputStream;
import java.security.cert.CRL;
import java.util.List;

public interface CrlReader {

  List<CRL> read(InputStream inputStream);

}
