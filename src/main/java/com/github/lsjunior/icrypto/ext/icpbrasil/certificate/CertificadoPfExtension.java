package com.github.lsjunior.icrypto.ext.icpbrasil.certificate;

import java.text.Normalizer;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.api.model.AlternativeNameType;
import com.github.lsjunior.icrypto.api.model.SubjectAlternativeName;
import com.github.lsjunior.icrypto.core.certificate.CertificateParameters;
import com.google.common.base.Strings;

public class CertificadoPfExtension extends IcpBrasilExtension {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private DadoPessoa dadoTitular;

  private DadoConselhoFederal dadoConselhoFederal;

  private String tituloEleitor;

  private String cei;

  private String ric;

  private String registroSincor;

  private String registroOab;

  public CertificadoPfExtension() {
    super();
  }

  @Override
  public CertificateParameters extend(final CertificateParameters request) {
    CertificateParameters r = super.extend(request);

    DadoPessoa dadoPessoa = this.getDadoTitular();
    String dadosTitular = dadoPessoa != null ? dadoPessoa.toString() : null;
    // https://www.alvestrand.no/objectid/2.16.76.1.3.5.html
    // TODO Tem os outros 22 caracteres da UF e municipio
    String str = this.getTituloEleitor();
    String tituloEleitor = IcpBrasilHelper.getNumericValue(str, 19);
    String cei = IcpBrasilHelper.getNumericValue(this.getCei(), 12);
    String ric = IcpBrasilHelper.getTextValue(this.getRic(), 11);

    if ((str != null) && (str.length() > 19)) {
      tituloEleitor += Normalizer.normalize(str.substring(19).trim(), Normalizer.Form.NFD).replaceAll("[^\\p{ASCII}]", "");
    }

    r.getAlternativeNames().add(new SubjectAlternativeName(ConstantesIcp.OID_PF_DADOS_TITULAR, dadosTitular, AlternativeNameType.OTHER_NAME));
    r.getAlternativeNames().add(new SubjectAlternativeName(ConstantesIcp.OID_PF_TITULO_ELEITOR, tituloEleitor, AlternativeNameType.OTHER_NAME));
    r.getAlternativeNames().add(new SubjectAlternativeName(ConstantesIcp.OID_PF_NUMERO_CEI, cei, AlternativeNameType.OTHER_NAME));
    r.getAlternativeNames().add(new SubjectAlternativeName(ConstantesIcp.OID_PF_NUMERO_RIC, ric, AlternativeNameType.OTHER_NAME));

    if (!Strings.isNullOrEmpty(this.getRegistroSincor())) {
      r.getAlternativeNames().add(new SubjectAlternativeName(ConstantesIcp.OID_PF_REGISTRO_SINCOR, this.getRegistroSincor(), AlternativeNameType.OTHER_NAME));
    }

    if (!Strings.isNullOrEmpty(this.getRegistroOab())) {
      r.getAlternativeNames().add(new SubjectAlternativeName(ConstantesIcp.OID_PF_REGISTRO_OAB, this.getRegistroOab(), AlternativeNameType.OTHER_NAME));
    }

    if (this.dadoConselhoFederal != null) {
      String prefix = this.dadoConselhoFederal.getTipo().getPrefix();
      r.getAlternativeNames().add(new SubjectAlternativeName(prefix + ConstantesIcp.SUFFIX_OID_CONSELHO_NUMERO, this.dadoConselhoFederal.getNumero(), AlternativeNameType.OTHER_NAME));
      r.getAlternativeNames().add(new SubjectAlternativeName(prefix + ConstantesIcp.SUFFIX_OID_CONSELHO_UF, this.dadoConselhoFederal.getUf(), AlternativeNameType.OTHER_NAME));
      r.getAlternativeNames().add(new SubjectAlternativeName(prefix + ConstantesIcp.SUFFIX_OID_CONSELHO_ESPECIALIDADE, this.dadoConselhoFederal.getEspecialidade(), AlternativeNameType.OTHER_NAME));
    }

    return r;
  }

  public DadoPessoa getDadoTitular() {
    return this.dadoTitular;
  }

  public void setDadoTitular(final DadoPessoa dadoTitular) {
    this.dadoTitular = dadoTitular;
  }

  public DadoConselhoFederal getDadoConselhoFederal() {
    return this.dadoConselhoFederal;
  }

  public void setDadoConselhoFederal(final DadoConselhoFederal dadoConselhoFederal) {
    this.dadoConselhoFederal = dadoConselhoFederal;
  }

  public String getTituloEleitor() {
    return this.tituloEleitor;
  }

  public void setTituloEleitor(final String tituloEleitor) {
    this.tituloEleitor = tituloEleitor;
  }

  public String getCei() {
    return this.cei;
  }

  public void setCei(final String cei) {
    this.cei = cei;
  }

  public String getRic() {
    return this.ric;
  }

  public void setRic(final String ric) {
    this.ric = ric;
  }

  public String getRegistroSincor() {
    return this.registroSincor;
  }

  public void setRegistroSincor(final String registroSincor) {
    this.registroSincor = registroSincor;
  }

  public String getRegistroOab() {
    return this.registroOab;
  }

  public void setRegistroOab(final String registroOab) {
    this.registroOab = registroOab;
  }

}
