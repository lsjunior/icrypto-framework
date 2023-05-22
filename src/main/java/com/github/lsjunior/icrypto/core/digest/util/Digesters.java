package com.github.lsjunior.icrypto.core.digest.util;

import com.github.lsjunior.icrypto.api.type.DigestType;
import com.github.lsjunior.icrypto.core.digest.Digester;
import com.github.lsjunior.icrypto.core.digest.impl.DigesterImpl;

public abstract class Digesters {

  public static final Digester MD2 = new DigesterImpl(DigestType.MD2);

  public static final Digester MD5 = new DigesterImpl(DigestType.MD5);

  public static final Digester SHA1 = new DigesterImpl(DigestType.SHA1);

  public static final Digester SHA256 = new DigesterImpl(DigestType.SHA256);

  public static final Digester SHA384 = new DigesterImpl(DigestType.SHA384);

  public static final Digester SHA512 = new DigesterImpl(DigestType.SHA512);

  private Digesters() {
    //
  }

  public static Digester getDigester(final DigestType type) {
    switch (type) {
      case MD2:
        return Digesters.MD2;
      case MD5:
        return Digesters.MD5;
      case SHA1:
        return Digesters.SHA1;
      case SHA256:
        return Digesters.SHA256;
      case SHA384:
        return Digesters.SHA384;
      case SHA512:
        return Digesters.SHA512;
      default:
        return new DigesterImpl(type);
    }
  }

}
