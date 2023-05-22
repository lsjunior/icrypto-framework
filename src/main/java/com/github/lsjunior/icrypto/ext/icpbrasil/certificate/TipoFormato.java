package com.github.lsjunior.icrypto.ext.icpbrasil.certificate;

public enum TipoFormato {

  A1("Assinatura A1"), /**/
  A2("Assinatura A2"), /**/
  A3("Assinatura A3"), /**/
  A4("Assinatura A4"), /**/
  S1("Sigilo S1"), /**/
  S2("Sigilo S2"), /**/
  S3("Sigilo S3"), /**/
  S4("Sigilo S4"), /**/
  T3("Carimbo de tempo T3"), /**/
  T4("Carimbo de tempo T4"), /**/
  DESCONHECIDO("Desconhecido");

  private String label;

  private TipoFormato(final String label) {
    this.label = label;
  }

  @Override
  public String toString() {
    return this.label;
  }

}
