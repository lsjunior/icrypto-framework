package com.github.lsjunior.icrypto.ext.icpbrasil.certificate;

public enum TipoConselhoFederal {

  // @formatter:off
  CFM    (ConstantesIcp.PREFIX_OID_CFM, "Conselho Federal de Medicina"),
  CFF    (ConstantesIcp.PREFIX_OID_CFF, "Conselho Federal de Farmácia"),
  CFBIO  (ConstantesIcp.PREFIX_OID_CFBIO, "Conselho Federal de Biologia"),
  CFBM   (ConstantesIcp.PREFIX_OID_CFBM, "Conselho Federal de Biomedicina"),
  CONFEF (ConstantesIcp.PREFIX_OID_CONFEF, "Conselho Federal de Educação Física"),
  COFEN  (ConstantesIcp.PREFIX_OID_COFEN, "Conselho Federal de Enfermagem"),
  COFFIT (ConstantesIcp.PREFIX_OID_COFFITO, "Conselho Federal de Fisioterapia e Terapia Ocupacional "),
  CFFA   (ConstantesIcp.PREFIX_OID_CFFA, "Conselho Federal de Fonoaudiologia"),
  CFMV   (ConstantesIcp.PREFIX_OID_CFMV , "Conselho Federal de Medicina Veterinária"),
  CFN    (ConstantesIcp.PREFIX_OID_CFN , "Conselho Federal de Nutricionistas"),
  CFO    (ConstantesIcp.PREFIX_OID_CFO, "Conselho Federal de Odontologia"),
  CFP    (ConstantesIcp.PREFIX_OID_CFP, "Conselho Federal de Psicologia"),
  CFESS  (ConstantesIcp.PREFIX_OID_CFESS, "Conselho Federal de Serviço Social"),
  CONTER (ConstantesIcp.PREFIX_OID_CONTER, "Conselho Nacional de Técnicos em Radiologi"),
  CFQ    (ConstantesIcp.PREFIX_OID_CFQ, "Conselho Federal de Química");
  //@formatter:on

  private String prefix;
  
  private String label;

  private TipoConselhoFederal(final String prefix, final String label) {
    this.prefix = prefix;
    this.label = label;
  }

  public String getPrefix() {
    return this.prefix;
  }
  
  public String getLabel() {
    return this.label;
  }

}
