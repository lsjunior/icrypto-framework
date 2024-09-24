package com.github.lsjunior.icrypto.ext.icpbrasil.certificate;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.x509.PolicyQualifierId;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.core.certificate.CertificateExtension;
import com.github.lsjunior.icrypto.core.certificate.CertificateParameters;
import com.google.common.base.Strings;

public abstract class IcpBrasilExtension implements CertificateExtension, Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private static final String URL_DEFAULT = "http://www.woodstock.net.br";

  private TipoFormato tipoFormato;

  public IcpBrasilExtension() {
    super();
  }

  @Override
  public CertificateParameters extend(final CertificateParameters request) {
    TipoFormato tipoFormato = this.getTipoFormato();
    if (tipoFormato != null) {
      String key = null;
      switch (tipoFormato) {
        case A1:
          key = ConstantesIcp.OID_A1_AC_SERASA;
          break;
        case A2:
          key = ConstantesIcp.OID_A2_AC_SERASA;
          break;
        case A3:
          key = ConstantesIcp.OID_A3_AC_SERASA;
          break;
        case A4:
          key = ConstantesIcp.OID_A4_AC_SERASA;
          break;
        default:
          break;
      }
      if (!Strings.isNullOrEmpty(key)) {
        Map<String, String> map = new HashMap<>();
        map.put(PolicyQualifierId.id_qt_cps.getId(), IcpBrasilExtension.URL_DEFAULT);
        request.getCertificatePolicies().put(key, map);
      }
    }
    return request;
  }

  public TipoFormato getTipoFormato() {
    return this.tipoFormato;
  }

  public void setTipoFormato(final TipoFormato tipoFormato) {
    this.tipoFormato = tipoFormato;
  }

}
