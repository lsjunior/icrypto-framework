package com.github.lsjunior.icrypto.core.signature.pades;

import java.io.IOException;
import java.io.InputStream;

import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;

import com.github.lsjunior.icrypto.core.signature.cms.CadesSignature;

public class CadesSignatureInterface extends CadesSignatureAdapter implements SignatureInterface {

  private CadesSignature signature;

  public CadesSignatureInterface(final PadesSignatureParameters parameters) {
    super(parameters);
  }

  public int preSign() throws IOException {
    return this.doPreSign();
  }

  @Override
  public byte[] sign(final InputStream content) throws IOException {
    this.signature = this.doSign(content);
    return this.signature.getData().read();
  }

  public CadesSignature getSignature() {
    return this.signature;
  }

}
