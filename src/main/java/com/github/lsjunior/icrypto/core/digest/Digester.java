package com.github.lsjunior.icrypto.core.digest;

import com.github.lsjunior.icrypto.api.type.DigestType;
import com.google.common.io.ByteSource;

public interface Digester {

  String getAlgorithm();

  DigestType getType();

  byte[] digest(byte[] data);

  byte[] digest(String data);

  byte[] digest(ByteSource source);

}
