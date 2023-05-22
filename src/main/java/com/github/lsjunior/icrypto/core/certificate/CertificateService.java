package com.github.lsjunior.icrypto.core.certificate;

import com.github.lsjunior.icrypto.core.Identity;

public interface CertificateService {

  Identity generate(CertificateParameters request);

}
