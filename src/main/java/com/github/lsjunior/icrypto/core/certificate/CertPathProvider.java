package com.github.lsjunior.icrypto.core.certificate;

import java.security.cert.CertPath;
import java.security.cert.CertPathBuilderException;
import java.security.cert.Certificate;

public interface CertPathProvider {

  CertPath getCertPath(final Certificate certificate) throws CertPathBuilderException;

}
