package com.github.lsjunior.icrypto.core.util;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import com.github.lsjunior.icrypto.ICryptoException;

public abstract class AbstractPemReader<T> {

  private String type;

  public AbstractPemReader(final String type) {
    super();
    this.type = type;
  }

  public List<T> read(final InputStream inputStream) {
    try {
      Reader reader = new InputStreamReader(inputStream);
      PemReader pemReader = new PemReader(reader);
      List<T> list = new ArrayList<>();
      PemObject pemObject = null;
      while ((pemObject = pemReader.readPemObject()) != null) {
        if (this.type.equals(pemObject.getType())) {
          T obj = this.toObject(pemObject.getContent());
          list.add(obj);
        }
      }
      pemReader.close();
      reader.close();
      return list;
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }

  protected abstract T toObject(byte[] bytes) throws Exception;

}
