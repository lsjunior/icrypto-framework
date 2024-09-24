package com.github.lsjunior.icrypto.core.certificate;

import java.io.OutputStream;
import java.security.PrivateKey;

public interface PrivateKeyWriter {

  void write(PrivateKey privateKey, OutputStream outputStream);

}
