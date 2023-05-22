package com.github.lsjunior.icrypto.core.util;

import java.io.OutputStream;
import java.io.StringWriter;
import java.util.List;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import com.github.lsjunior.icrypto.ICryptoException;

public abstract class AbstractPemWriter<T> {

  private String type;

  public AbstractPemWriter(final String type) {
    super();
    this.type = type;
  }

  public void write(final List<T> list, final OutputStream outputStream) {
    try {
      StringWriter writer = new StringWriter();
      PemWriter pemWriter = new JcaPEMWriter(writer);
      for (T obj : list) {
        PemObject pemObject = new PemObject(this.type, this.toByteArray(obj));
        pemWriter.writeObject(pemObject);
      }
      pemWriter.close();
      outputStream.write(writer.getBuffer().toString().getBytes());
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }

  protected abstract byte[] toByteArray(final T t) throws Exception;

}
