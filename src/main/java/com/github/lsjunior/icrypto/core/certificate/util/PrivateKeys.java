package com.github.lsjunior.icrypto.core.certificate.util;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.Collections;

import com.github.lsjunior.icrypto.core.certificate.impl.PemPrivateKeyWriter;

public abstract class PrivateKeys {

  private PrivateKeys() {
    //
  }

  public static byte[] toByteArray(final PrivateKey key) {
    if (key != null) {
      return key.getEncoded();
    }
    return null;
  }

  public static byte[] toPemByteArray(final PrivateKey key) {
    if (key != null) {
      ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
      PemPrivateKeyWriter.getInstance().write(Collections.singletonList(key), outputStream);
      byte[] bytes = outputStream.toByteArray();
      return bytes;
    }
    return null;
  }

  public static String toPemString(final PrivateKey key) {
    if (key != null) {
      byte[] bytes = PrivateKeys.toPemByteArray(key);
      String str = new String(bytes, StandardCharsets.UTF_8);
      return str;
    }
    return null;
  }

}
