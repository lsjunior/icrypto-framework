package com.github.lsjunior.icrypto.ext.icpbrasil.certificate;

import java.security.cert.X509Certificate;
import java.util.Date;

public class CertificadoPj extends CertificadoIcp {

  private String responsavel;

  private String cnpj;

  private String cei;

  private String nomeEmpresarial;

  CertificadoPj(final X509Certificate certificate) {
    super(certificate);
    this.setTipoPessoa(TipoPessoa.PESSOA_JURIDICA);
  }

  public String getResponsavel() {
    return this.responsavel;
  }

  void setResponsavel(final String responsavel) {
    this.responsavel = responsavel;
  }

  public String getCnpj() {
    return this.cnpj;
  }

  void setCnpj(final String cnpj) {
    this.cnpj = cnpj;
  }

  public String getCei() {
    return this.cei;
  }

  void setCei(final String cei) {
    this.cei = cei;
  }

  public String getNomeEmpresarial() {
    return this.nomeEmpresarial;
  }

  void setNomeEmpresarial(final String nomeEmpresarial) {
    this.nomeEmpresarial = nomeEmpresarial;
  }

  // Delegate
  public Date getDataNascimentoResponsavel() {
    if (this.getDadoPessoa() == null) {
      return null;
    }
    return this.getDadoPessoa().getDataNascimento();
  }

  public String getCpfResponsavel() {
    if (this.getDadoPessoa() == null) {
      return null;
    }
    return this.getDadoPessoa().getCpf();
  }

  public String getPisResponsavel() {
    if (this.getDadoPessoa() == null) {
      return null;
    }
    return this.getDadoPessoa().getPis();
  }

  public String getRgResponsavel() {
    if (this.getDadoPessoa() == null) {
      return null;
    }
    return this.getDadoPessoa().getRg();
  }

  public String getEmissorRgResponsavel() {
    if (this.getDadoPessoa() == null) {
      return null;
    }
    return this.getDadoPessoa().getEmissorRg();
  }

}
