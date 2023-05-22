package com.github.lsjunior.icrypto.ext.icpbrasil.certificate;

import java.io.Serializable;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.core.certificate.CertificateValidator;
import com.github.lsjunior.icrypto.core.certificate.ValidationError;

public class IcpBrasilCertificateValidator implements CertificateValidator, Serializable {

  public static final String VALIDATOR_NAME = "ICP Brasil Validator";

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private TipoFormato[] tiposFormato;

  public IcpBrasilCertificateValidator() {
    super();
  }

  public IcpBrasilCertificateValidator(final TipoFormato[] tiposFormato) {
    super();
    this.tiposFormato = tiposFormato;
  }

  @Override
  public Collection<ValidationError> validate(final List<Certificate> chain) {
    X509Certificate x509Certificate = (X509Certificate) chain.get(0);
    CertificadoIcp certificadoICPBrasil = CertificadoIcp.getInstance(x509Certificate);
    List<ValidationError> list = new ArrayList<>();

    if (certificadoICPBrasil.getTipoPessoa() == TipoPessoa.DESCONHECIDO) {
      list.add(new ValidationError(IcpBrasilCertificateValidator.VALIDATOR_NAME, "Tipo do proprietário do certificado inválido(PF/PJ)"));
    }

    if (this.tiposFormato != null) {
      boolean ok = false;
      for (TipoFormato tipoFormato : this.tiposFormato) {
        if (tipoFormato.equals(certificadoICPBrasil.getTipoFormato())) {
          ok = true;
          break;
        }
      }
      if (!ok) {
        list.add(new ValidationError(IcpBrasilCertificateValidator.VALIDATOR_NAME, "Formato do certificado inválido(A1,A2,A3,A4)"));
      }
    }

    return list;
  }
}
