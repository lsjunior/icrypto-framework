package com.github.lsjunior.icrypto.core;

import java.io.Serializable;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.List;

import com.github.lsjunior.icrypto.ICryptoConstants;

public class Identity implements Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private final PrivateKey privateKey;

  private List<Certificate> chain;

  public Identity(final PrivateKey privateKey, final Certificate certificate) {
    super();
    this.privateKey = privateKey;
    if (certificate != null) {
      this.chain = Collections.unmodifiableList(Collections.singletonList(certificate));
    }
  }

  public Identity(final PrivateKey privateKey, final List<Certificate> chain) {
    super();
    this.privateKey = privateKey;
    this.chain = chain;
  }

  public PrivateKey getPrivateKey() {
    return this.privateKey;
  }

  public List<Certificate> getChain() {
    return this.chain;
  }

  @Override
  public String toString() {
    if ((this.chain != null) && (!this.chain.isEmpty())) {
      return this.chain.get(0).toString();
    }
    if (this.privateKey != null) {
      return this.privateKey.toString();
    }

    return super.toString();
  }

}
