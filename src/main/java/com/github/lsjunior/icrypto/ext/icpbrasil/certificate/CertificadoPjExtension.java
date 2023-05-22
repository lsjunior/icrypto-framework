package com.github.lsjunior.icrypto.ext.icpbrasil.certificate;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.api.model.AlternativeNameType;
import com.github.lsjunior.icrypto.api.model.SubjectAlternativeName;
import com.github.lsjunior.icrypto.core.certificate.CertificateParameters;

public class CertificadoPjExtension extends IcpBrasilExtension {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private String responsavel;

  private String cnpj;

  private DadoPessoa dadoResponsavel;

  private String cei;

  private String nomeEmpresarial;

  public CertificadoPjExtension() {
    super();
  }

  @Override
  public CertificateParameters extend(final CertificateParameters request) {
    CertificateParameters r = super.extend(request);
    DadoPessoa dadoPessoa = this.getDadoResponsavel();
    String responsavel = IcpBrasilHelper.getValue(this.getResponsavel());
    String cnpj = IcpBrasilHelper.getNumericValue(this.getCnpj(), 14);
    String dadosResponsavel = dadoPessoa != null ? dadoPessoa.toString() : null;
    String cei = IcpBrasilHelper.getNumericValue(this.getCei(), 12);
    String nomeEmpresarial = IcpBrasilHelper.getValue(this.getNomeEmpresarial());

    r.getAlternativeNames().add(new SubjectAlternativeName(ConstantesIcp.OID_PJ_NOME_RESPONSAVEL, responsavel, AlternativeNameType.OTHER_NAME));
    r.getAlternativeNames().add(new SubjectAlternativeName(ConstantesIcp.OID_PJ_NUMERO_CNPJ, cnpj, AlternativeNameType.OTHER_NAME));
    r.getAlternativeNames().add(new SubjectAlternativeName(ConstantesIcp.OID_PJ_DADOS_RESPONSAVEL, dadosResponsavel, AlternativeNameType.OTHER_NAME));
    r.getAlternativeNames().add(new SubjectAlternativeName(ConstantesIcp.OID_PJ_NUMERO_CEI, cei, AlternativeNameType.OTHER_NAME));
    r.getAlternativeNames().add(new SubjectAlternativeName(ConstantesIcp.OID_PJ_NOME_EMPRESARIAL, nomeEmpresarial, AlternativeNameType.OTHER_NAME));

    return r;
  }

  public String getResponsavel() {
    return this.responsavel;
  }

  public void setResponsavel(final String responsavel) {
    this.responsavel = responsavel;
  }

  public String getCnpj() {
    return this.cnpj;
  }

  public void setCnpj(final String cnpj) {
    this.cnpj = cnpj;
  }

  public DadoPessoa getDadoResponsavel() {
    return this.dadoResponsavel;
  }

  public void setDadoResponsavel(final DadoPessoa dadoResponsavel) {
    this.dadoResponsavel = dadoResponsavel;
  }

  public String getCei() {
    return this.cei;
  }

  public void setCei(final String cei) {
    this.cei = cei;
  }

  public String getNomeEmpresarial() {
    return this.nomeEmpresarial;
  }

  public void setNomeEmpresarial(final String nomeEmpresarial) {
    this.nomeEmpresarial = nomeEmpresarial;
  }

}
