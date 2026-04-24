package com.github.lsjunior.icrypto.core.signature.pades;

import java.io.Serializable;

/**
 * @deprecated Use {@link OpenPdfService} instead.
 */
@Deprecated(forRemoval = true)
public class ITextPdfService extends AbstractPadesService implements Serializable {

  private static final ITextPdfService INSTANCE = new ITextPdfService();

  public ITextPdfService() {
    super();
  }

  public static ITextPdfService getInstance() {
    return ITextPdfService.INSTANCE;
  }

  @Override
  public PadesSignature sign(final PadesSignatureParameters parameters) {
    return OpenPdfService.getInstance().sign(parameters);
  }

  @Override
  public PadesVerificationResult verify(final PadesVerificationParameters parameters) {
    return OpenPdfService.getInstance().verify(parameters);
  }

}
