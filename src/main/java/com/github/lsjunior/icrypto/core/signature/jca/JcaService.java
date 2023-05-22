package com.github.lsjunior.icrypto.core.signature.jca;

import java.io.IOException;
import java.io.Serializable;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.ICryptoException;
import com.github.lsjunior.icrypto.api.type.SignatureType;
import com.google.common.base.Strings;
import com.google.common.io.ByteSource;

public class JcaService implements Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  public JcaService() {
    super();
  }

  public byte[] sign(final PrivateKey privateKey, final SignatureType type, final ByteSource source) {
    return this.sign(privateKey, type, source, null);
  }

  public byte[] sign(final PrivateKey privateKey, final SignatureType type, final ByteSource source, final String provider) {
    try {
      Signature s = null;
      if (!Strings.isNullOrEmpty(provider)) {
        s = Signature.getInstance(type.getAlgorithm(), provider);
      } else {
        s = Signature.getInstance(type.getAlgorithm());
      }

      s.initSign(privateKey);

      SignatureOutputStream signatureOutputStream = new SignatureOutputStream(s);
      source.copyTo(signatureOutputStream);

      byte[] bytes = signatureOutputStream.sign();
      return bytes;
    } catch (GeneralSecurityException | IOException e) {
      throw new ICryptoException(e);
    }
  }

  public boolean verify(final Certificate certificate, final  SignatureType type, final ByteSource source, final byte[] signature) {
    return this.verify(certificate.getPublicKey(), type, source, signature, null);
  }

  public boolean verify(final Certificate certificate, final  SignatureType type, final ByteSource source, final byte[] signature, final String provider) {
    return this.verify(certificate.getPublicKey(), type, source, signature, provider);
  }

  public boolean verify(final PublicKey publicKey, final  SignatureType type, final ByteSource source, final byte[] signature) {
    return this.verify(publicKey, type, source, signature, null);
  }

  public boolean verify(final PublicKey publicKey, final  SignatureType type, final ByteSource source, final byte[] signature, final String provider) {
    try {
      Signature s = null;
      if (!Strings.isNullOrEmpty(provider)) {
        s = Signature.getInstance(type.getAlgorithm(), provider);
      } else {
        s = Signature.getInstance(type.getAlgorithm());
      }

      s.initVerify(publicKey);

      SignatureOutputStream signatureOutputStream = new SignatureOutputStream(s);
      source.copyTo(signatureOutputStream);
      boolean valid = signatureOutputStream.verify(signature);
      return valid;
    } catch (GeneralSecurityException | IOException e) {
      throw new ICryptoException(e);
    }
  }

}
