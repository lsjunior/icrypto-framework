package com.github.lsjunior.icrypto.core.signature.pades;

public interface PadesService {

  PadesSignature sign(PadesSignatureParameters parameters);

  PadesVerificationResult verify(PadesVerificationParameters parameters);

}
