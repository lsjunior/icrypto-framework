package com.github.lsjunior.icrypto.core.certificate;

import java.io.InputStream;
import java.security.cert.Certificate;
import java.util.List;

public interface CertificateReader {

  List<Certificate> read(InputStream inputStream);

}
