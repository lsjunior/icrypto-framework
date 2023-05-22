package com.github.lsjunior.icrypto.core.certificate;

import java.security.cert.Certificate;
import java.util.Collection;
import java.util.List;

public interface CertificateValidator {

  Collection<ValidationError> validate(List<Certificate> chain);

}
