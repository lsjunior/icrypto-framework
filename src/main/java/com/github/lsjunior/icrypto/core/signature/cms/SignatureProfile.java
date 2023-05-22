package com.github.lsjunior.icrypto.core.signature.cms;

public interface SignatureProfile {

  void extend(CadesSignatureContext context);

  void verify(VerificationContext context);

}
