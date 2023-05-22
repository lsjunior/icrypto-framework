package com.github.lsjunior.icrypto.ext.icpbrasil.certificate;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import com.github.lsjunior.icrypto.ICryptoException;
import com.github.lsjunior.icrypto.core.certificate.DelegateX509Certificate;

public abstract class CertificadoIcp extends DelegateX509Certificate {

  private TipoPessoa tipoPessoa;

  private TipoFormato tipoFormato;

  private DadoPessoa dadoPessoa;

  private String email;

  private String dominio;

  public CertificadoIcp(final X509Certificate certificate) {
    super(certificate);
  }

  public TipoPessoa getTipoPessoa() {
    return this.tipoPessoa;
  }

  void setTipoPessoa(final TipoPessoa tipoPessoa) {
    this.tipoPessoa = tipoPessoa;
  }

  public TipoFormato getTipoFormato() {
    return this.tipoFormato;
  }

  void setTipoFormato(final TipoFormato tipoFormato) {
    this.tipoFormato = tipoFormato;
  }

  public DadoPessoa getDadoPessoa() {
    return this.dadoPessoa;
  }

  void setDadoPessoa(final DadoPessoa dadoPessoa) {
    this.dadoPessoa = dadoPessoa;
  }

  public String getEmail() {
    return this.email;
  }

  void setEmail(final String email) {
    this.email = email;
  }

  public String getDominio() {
    return this.dominio;
  }

  public void setDominio(final String dominio) {
    this.dominio = dominio;
  }

  public static CertificadoIcp getInstance(final Certificate certificate) {
    return CertificadoIcp.getInstance((X509Certificate) certificate);
  }

  public static CertificadoIcp getInstance(final X509Certificate certificate) {
    try {
      if (certificate == null) {
        return null;
      }
      if (certificate instanceof CertificadoIcp) {
        return (CertificadoIcp) certificate;
      }
      return IcpBrasilHelper.getCertificadoICPBrasil(certificate);
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }
}
