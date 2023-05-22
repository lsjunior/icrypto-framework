package com.github.lsjunior.icrypto.ext.icpbrasil.certificate;

import java.io.Serializable;

import com.github.lsjunior.icrypto.ICryptoConstants;

public class DadoConselhoFederal implements Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private String numero;

  private String uf;

  private String especialidade;

  private TipoConselhoFederal tipo;

  public DadoConselhoFederal() {
    super();
  }

  public DadoConselhoFederal(final String numero, final String uf, final String especialidade, final TipoConselhoFederal tipo) {
    super();
    this.numero = numero;
    this.uf = uf;
    this.especialidade = especialidade;
    this.tipo = tipo;
  }

  public String getNumero() {
    return this.numero;
  }

  public void setNumero(final String numero) {
    this.numero = numero;
  }

  public String getUf() {
    return this.uf;
  }

  public void setUf(final String uf) {
    this.uf = uf;
  }

  public String getEspecialidade() {
    return this.especialidade;
  }

  public void setEspecialidade(final String especialidade) {
    this.especialidade = especialidade;
  }

  public TipoConselhoFederal getTipo() {
    return this.tipo;
  }

  public void setTipo(final TipoConselhoFederal tipo) {
    this.tipo = tipo;
  }

}
