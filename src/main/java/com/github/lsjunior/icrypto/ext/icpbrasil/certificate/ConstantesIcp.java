package com.github.lsjunior.icrypto.ext.icpbrasil.certificate;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public abstract class ConstantesIcp {

  // OIDs baseados no documento do ITI, versao 2.11 de 05/06/212
  // http://www.iti.gov.br/component/content/article/84-legislacao/777-adendos
  // http://www.iti.gov.br/images/twiki/URL/pub/Certificacao/AdeIcp/ADE-ICP-04.01_Vers%C3%A3o_2.14.pdf

  public static final Charset DEFAULT_CHARSET = StandardCharsets.ISO_8859_1;

  // PF
  public static final String OID_PF_DADOS_TITULAR = "2.16.76.1.3.1";

  public static final String OID_PF_TITULO_ELEITOR = "2.16.76.1.3.5";

  public static final String OID_PF_NUMERO_CEI = "2.16.76.1.3.6";

  // Registro de Identidade Civil
  public static final String OID_PF_NUMERO_RIC = "2.16.76.1.3.9";

  public static final String OID_PF_REGISTRO_SIGEPE = "2.16.76.1.3.11";

  public static final String OID_PF_REGISTRO_SINCOR = "2.16.76.1.4.1.1.1";

  public static final String OID_PF_REGISTRO_OAB = "2.16.76.1.4.2.1.1";

  public static final String OID_PF_NOME_SOCIAL = "2.16.76.1.4.3";

  // PJ
  public static final String OID_PJ_NOME_RESPONSAVEL = "2.16.76.1.3.2";

  public static final String OID_PJ_NUMERO_CNPJ = "2.16.76.1.3.3";

  public static final String OID_PJ_DADOS_RESPONSAVEL = "2.16.76.1.3.4";

  public static final String OID_PJ_NUMERO_CEI = "2.16.76.1.3.7";

  public static final String OID_PJ_NOME_EMPRESARIAL = "2.16.76.1.3.8";

  public static final String OID_PJ_DADO_ESAT = "2.16.76.1.3.10";

  // OID Conselho
  public static final String PREFIX_OID_CFM = "2.16.76.1.4.2.2";

  public static final String PREFIX_OID_CFF = "2.16.76.1.4.2.3";

  public static final String PREFIX_OID_CFBIO = "2.16.76.1.4.2.4";

  public static final String PREFIX_OID_CFBM = "2.16.76.1.4.2.5";

  public static final String PREFIX_OID_CONFEF = "2.16.76.1.4.2.6";

  public static final String PREFIX_OID_COFEN = "2.16.76.1.4.2.7";

  public static final String PREFIX_OID_COFFITO = "2.16.76.1.4.2.8";

  public static final String PREFIX_OID_CFFA = "2.16.76.1.4.2.9";

  public static final String PREFIX_OID_CFMV = "2.16.76.1.4.2.10";

  public static final String PREFIX_OID_CFN = "2.16.76.1.4.2.11";

  public static final String PREFIX_OID_CFO = "2.16.76.1.4.2.12";

  public static final String PREFIX_OID_CFP = "2.16.76.1.4.2.13";

  public static final String PREFIX_OID_CFESS = "2.16.76.1.4.2.14";

  public static final String PREFIX_OID_CONTER = "2.16.76.1.4.2.15";

  public static final String PREFIX_OID_CFQ = "2.16.76.1.4.2.16";

  public static final String SUFFIX_OID_CONSELHO_NUMERO = ".1";

  public static final String SUFFIX_OID_CONSELHO_UF = ".2";

  public static final String SUFFIX_OID_CONSELHO_ESPECIALIDADE = ".3";

  // OID Formato
  public static final String PREFIX_OID_A1 = "2.16.76.1.2.1.";

  public static final String PREFIX_OID_A2 = "2.16.76.1.2.2.";

  public static final String PREFIX_OID_A3 = "2.16.76.1.2.3.";

  public static final String PREFIX_OID_A4 = "2.16.76.1.2.4.";

  public static final String PREFIX_OID_S1 = "2.16.76.1.2.101.";

  public static final String PREFIX_OID_S2 = "2.16.76.1.2.102.";

  public static final String PREFIX_OID_S3 = "2.16.76.1.2.103.";

  public static final String PREFIX_OID_S4 = "2.16.76.1.2.104.";

  public static final String PREFIX_OID_T3 = "2.16.76.1.2.303.";

  public static final String PREFIX_OID_T4 = "2.16.76.1.2.304.";

  public static final String PREFIX_OID_AC_ICPBRASIL = "2.16.76.1.2.201";

  public static final String OID_A1_AC_SERASA = ConstantesIcp.PREFIX_OID_A1 + "2";

  public static final String OID_A2_AC_SERASA = ConstantesIcp.PREFIX_OID_A2 + "1";

  public static final String OID_A3_AC_SERASA = ConstantesIcp.PREFIX_OID_A3 + "3";

  public static final String OID_A4_AC_SERASA = ConstantesIcp.PREFIX_OID_A4 + "1";

  public static final String OID_S1_AC_SERASA = ConstantesIcp.PREFIX_OID_S1 + "1";

  public static final String OID_S2_AC_SERASA = ConstantesIcp.PREFIX_OID_S2 + "1";

  public static final String OID_S3_AC_SERASA = ConstantesIcp.PREFIX_OID_S3 + "1";

  public static final String OID_S4_AC_SERASA = ConstantesIcp.PREFIX_OID_S4 + "1";

  public static final String OID_T3_AC_SERASA = ConstantesIcp.PREFIX_OID_T3 + "2";

  public static final String OID_T4_AC_SERASA = ConstantesIcp.PREFIX_OID_T4 + "2";

  public static final String FORMATO_DATA = "ddMMyyyy";

  public static final char COMPLEMENTO_NUMERO = '0';

  public static final char COMPLEMENTO_TEXTO = ' ';

  // Saude
  public static final String PREFIX_OID_DOCUMENTO_SAUDE = "2.16.76.1.12.1";

  public static final String PREFIX_OID_DOCUMENTO_SAUDE_PRESCRICAO = "2.16.76.1.12.1.1";

  public static final String PREFIX_OID_DOCUMENTO_SAUDE_ATESTADO = "2.16.76.1.12.1.2";

  public static final String PREFIX_OID_DOCUMENTO_SAUDE_SOLICITACAO_EXAME = "2.16.76.1.12.1.3";

  public static final String PREFIX_OID_DOCUMENTO_SAUDE_LAUDO_LABORATORIAL = "2.16.76.1.12.1.4";

  public static final String PREFIX_OID_DOCUMENTO_SAUDE_SUMARIO_ALTA = "2.16.76.1.12.1.5";

  public static final String PREFIX_OID_DOCUMENTO_SAUDE_REGISTRO_ATENDIMENTO = "2.16.76.1.12.1.6";

  public static final String PREFIX_OID_DOCUMENTO_SAUDE_DISPENSACAO = "2.16.76.1.12.1.7";

  public static final String PREFIX_OID_DOCUMENTO_SAUDE_VACINACAO = "2.16.76.1.12.1.7";

  public static final String PREFIX_OID_DOCUMENTO_SAUDE_RELATORIO = "2.16.76.1.12.1.11";

  private ConstantesIcp() {
    //
  }

}
