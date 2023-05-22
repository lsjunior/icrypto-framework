package com.github.lsjunior.icrypto.ext.icpbrasil.certificate;

import java.security.cert.X509Certificate;
import java.util.Date;

public class CertificadoPf extends CertificadoIcp {

  private String nomeSocial;

  private String tituloEleitor;

  private String cei;

  private String ric;

  private String registroSincor;

  private String registroOab;

  private String registroSigepe;

  private DadoConselhoFederal dadoConselhoFederal;

  CertificadoPf(final X509Certificate certificate) {
    super(certificate);
    this.setTipoPessoa(TipoPessoa.PESSOA_FISICA);
  }

  public String getNomeSocial() {
    return this.nomeSocial;
  }

  public void setNomeSocial(final String nomeSocial) {
    this.nomeSocial = nomeSocial;
  }

  public String getTituloEleitor() {
    return this.tituloEleitor;
  }

  void setTituloEleitor(final String tituloEleitor) {
    this.tituloEleitor = tituloEleitor;
  }

  public String getCei() {
    return this.cei;
  }

  void setCei(final String cei) {
    this.cei = cei;
  }

  public String getRic() {
    return this.ric;
  }

  void setRic(final String ric) {
    this.ric = ric;
  }

  public String getRegistroSincor() {
    return this.registroSincor;
  }

  void setRegistroSincor(final String registroSincor) {
    this.registroSincor = registroSincor;
  }

  public String getRegistroOab() {
    return this.registroOab;
  }

  void setRegistroOab(final String registroOab) {
    this.registroOab = registroOab;
  }

  public String getRegistroSigepe() {
    return this.registroSigepe;
  }

  public void setRegistroSigepe(final String registroSigepe) {
    this.registroSigepe = registroSigepe;
  }

  public DadoConselhoFederal getDadoConselhoFederal() {
    return this.dadoConselhoFederal;
  }

  public void setDadoConselhoFederal(DadoConselhoFederal dadoConselhoFederal) {
    this.dadoConselhoFederal = dadoConselhoFederal;
  }

  // Delegate
  public Date getDataNascimento() {
    if (this.getDadoPessoa() == null) {
      return null;
    }
    return this.getDadoPessoa().getDataNascimento();
  }

  public String getCpf() {
    if (this.getDadoPessoa() == null) {
      return null;
    }
    return this.getDadoPessoa().getCpf();
  }

  public String getPis() {
    if (this.getDadoPessoa() == null) {
      return null;
    }
    return this.getDadoPessoa().getPis();
  }

  public String getRg() {
    if (this.getDadoPessoa() == null) {
      return null;
    }
    return this.getDadoPessoa().getRg();
  }

  public String getEmissorRg() {
    if (this.getDadoPessoa() == null) {
      return null;
    }
    return this.getDadoPessoa().getEmissorRg();
  }

}
