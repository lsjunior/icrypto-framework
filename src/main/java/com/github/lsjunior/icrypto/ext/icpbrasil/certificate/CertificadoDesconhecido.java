package com.github.lsjunior.icrypto.ext.icpbrasil.certificate;

import java.security.cert.X509Certificate;

public class CertificadoDesconhecido extends CertificadoIcp {

  CertificadoDesconhecido(final X509Certificate certificate) {
    super(certificate);
    this.setTipoFormato(TipoFormato.DESCONHECIDO);
    this.setTipoPessoa(TipoPessoa.DESCONHECIDO);
  }

}
