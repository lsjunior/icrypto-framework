package com.github.lsjunior.icrypto.core.certificate.impl;

import java.io.OutputStream;
import java.io.Serializable;
import java.security.PrivateKey;
import java.util.Collections;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.core.certificate.PrivateKeyWriter;
import com.github.lsjunior.icrypto.core.util.AbstractPemWriter;
import com.github.lsjunior.icrypto.core.util.PemTypes;

public class PemPrivateKeyWriter extends AbstractPemWriter<PrivateKey> implements PrivateKeyWriter, Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private static final PemPrivateKeyWriter INSTANCE = new PemPrivateKeyWriter();

  private PemPrivateKeyWriter() {
    super(PemTypes.PRIVATE_KEY);
  }

  @Override
  public void write(final PrivateKey privateKey, final OutputStream outputStream) {
    this.write(Collections.singletonList(privateKey), outputStream);
  }

  @Override
  protected byte[] toByteArray(final PrivateKey t) throws Exception {
    return t.getEncoded();
  }

  public static PemPrivateKeyWriter getInstance() {
    return PemPrivateKeyWriter.INSTANCE;
  }

}
