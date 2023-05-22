package com.github.lsjunior.icrypto.ext.icpbrasil.certificate;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.PolicyInformation;

import com.github.lsjunior.icrypto.core.util.Asn1Objects;
import com.google.common.base.Strings;

abstract class IcpBrasilHelper {

  public static String getValue(final String value) {
    if (value == null) {
      return "";
    }
    return value;
  }

  public static String getNumericValue(final String value, final int size) {
    String s = value;
    if (s == null) {
      s = "";
    }
    return IcpBrasilHelper.lpad(s, ConstantesIcp.COMPLEMENTO_NUMERO, size);
  }

  public static String getTextValue(final String value, final int size) {
    String s = value;
    if (s == null) {
      s = "";
    }
    return IcpBrasilHelper.rpad(s, ConstantesIcp.COMPLEMENTO_TEXTO, size);
  }

  public static String getDateValue(final Date value) {
    Date d = value;
    if (d == null) {
      d = new Date();
    }
    return new SimpleDateFormat(ConstantesIcp.FORMATO_DATA).format(d);
  }

  public static String getValueFromNumeric(final String numeric) {
    if (Strings.isNullOrEmpty(numeric)) {
      return null;
    }
    StringBuilder builder = new StringBuilder();
    char[] array = numeric.toCharArray();
    boolean add = false;
    for (int i = 0; i < array.length; i++) {
      if (add) {
        builder.append(array[i]);
      } else if (array[i] != ConstantesIcp.COMPLEMENTO_NUMERO) {
        add = true;
        builder.append(array[i]);
      }
    }
    return builder.toString();
  }

  public static Date getDateFromString(final String date) throws ParseException {
    if (Strings.isNullOrEmpty(date)) {
      return null;
    }
    return new SimpleDateFormat(ConstantesIcp.FORMATO_DATA).parse(date);
  }

  public static String toString(final byte[] bytes) {
    return new String(bytes, ConstantesIcp.DEFAULT_CHARSET);
  }

  public static CertificadoIcp getCertificadoICPBrasil(final X509Certificate certificate) throws GeneralSecurityException, IOException {
    Collection<List<?>> alternativeNames = certificate.getSubjectAlternativeNames();
    TipoPessoa tipoPessoa = TipoPessoa.DESCONHECIDO;
    TipoFormato tipoFormato = TipoFormato.DESCONHECIDO;
    CertificadoIcp certificadoICPBrasil = null;
    if ((alternativeNames != null) && (!alternativeNames.isEmpty())) {
      // Comum
      DadoPessoa dadoPessoa = null;
      String email = null;
      String dominio = null;
      // PF
      String nomeSocial = null;
      String tituloEleitorPf = null;
      String ceiPf = null;
      String ricPf = null;
      String registroSincorPf = null;
      String registroOabPf = null;
      String registroSigepe = null;
      DadoConselhoFederal dadoConselhoFederal = null;
      TipoConselhoFederal tipoConselhoFederal = null;
      String numeroConselhoFederal = null;
      String ufConselhoFederal = null;
      String especialidadeConselhoFederal = null;
      // PJ
      String responsavelPj = null;
      String cnpjPj = null;
      String ceiPj = null;
      String nomeEmpresarialPj = null;
      for (List<?> list : alternativeNames) {
        Integer tmp = (Integer) list.get(0);
        int id = tmp != null ? tmp.intValue() : -1;
        if (id == GeneralName.otherName) {
          byte[] bytes = (byte[]) list.get(1);
          ASN1Primitive primitive = Asn1Objects.toAsn1Primitive(bytes);
          String oid = null;
          String value = null;
          if (primitive instanceof ASN1TaggedObject) {
            ASN1TaggedObject tmpTaggedObject = (ASN1TaggedObject) primitive;
            ASN1Sequence sequence = (ASN1Sequence) tmpTaggedObject.toASN1Primitive();
            ASN1ObjectIdentifier identifier = (ASN1ObjectIdentifier) sequence.getObjectAt(0);
            ASN1Primitive string = ((ASN1TaggedObject) sequence.getObjectAt(1)).toASN1Primitive();
            oid = identifier.getId();
            value = Asn1Objects.toString(string, ConstantesIcp.DEFAULT_CHARSET);
          } else {
            ASN1Sequence sequence = (ASN1Sequence) primitive;
            ASN1ObjectIdentifier identifier = (ASN1ObjectIdentifier) sequence.getObjectAt(0);
            ASN1TaggedObject taggedObject = (ASN1TaggedObject) ((ASN1TaggedObject) sequence.getObjectAt(1)).toASN1Primitive();
            oid = identifier.getId();
            value = Asn1Objects.toString(taggedObject, ConstantesIcp.DEFAULT_CHARSET);
          }

          if (Strings.isNullOrEmpty(value)) {
            value = null;
          }

          if (ConstantesIcp.OID_PF_DADOS_TITULAR.equals(oid)) { // PF
            if (value != null) {
              dadoPessoa = DadoPessoa.getInstance(value);
            }
            tipoPessoa = TipoPessoa.PESSOA_FISICA;
          } else if (ConstantesIcp.OID_PF_NOME_SOCIAL.equals(oid)) {
            nomeSocial = value;
          } else if (ConstantesIcp.OID_PF_TITULO_ELEITOR.equals(oid)) {
            String str = IcpBrasilHelper.getValue(value);
            String num = IcpBrasilHelper.getValueFromNumeric(str);
            if ((num != null) && (!num.isEmpty())) {
              tituloEleitorPf = str.trim();
            }
          } else if (ConstantesIcp.OID_PF_NUMERO_CEI.equals(oid)) {
            ceiPf = IcpBrasilHelper.getValueFromNumeric(value);
          } else if (ConstantesIcp.OID_PF_NUMERO_RIC.equals(oid)) {
            ricPf = value;
          } else if (ConstantesIcp.OID_PF_REGISTRO_SINCOR.equals(oid)) {
            registroSincorPf = value;
          } else if (ConstantesIcp.OID_PF_REGISTRO_OAB.equals(oid)) {
            registroOabPf = value;
          } else if (ConstantesIcp.OID_PF_REGISTRO_SIGEPE.equals(oid)) {
            registroSigepe = IcpBrasilHelper.getValueFromNumeric(value);
          } else if (ConstantesIcp.OID_PJ_NOME_RESPONSAVEL.equals(oid)) { // PJ
            responsavelPj = value;
          } else if (ConstantesIcp.OID_PJ_NUMERO_CNPJ.equals(oid)) {
            cnpjPj = value;
            tipoPessoa = TipoPessoa.PESSOA_JURIDICA;
          } else if (ConstantesIcp.OID_PJ_DADOS_RESPONSAVEL.equals(oid)) {
            if (value != null) {
              dadoPessoa = DadoPessoa.getInstance(value);
            }
          } else if (ConstantesIcp.OID_PJ_NUMERO_CEI.equals(oid)) {
            ceiPj = IcpBrasilHelper.getValueFromNumeric(value);
          } else if (ConstantesIcp.OID_PJ_NOME_EMPRESARIAL.equals(oid)) {
            nomeEmpresarialPj = value;
          } else {
            // Conselhos
            for(TipoConselhoFederal item : TipoConselhoFederal.values()) {
              if (oid.startsWith(item.getPrefix())) {
                tipoConselhoFederal = item;
                if (oid.startsWith(item.getPrefix() + ConstantesIcp.SUFFIX_OID_CONSELHO_NUMERO)) {
                  // numero
                  numeroConselhoFederal = value;
                } else if (oid.startsWith(item.getPrefix() + ConstantesIcp.SUFFIX_OID_CONSELHO_UF)) {
                  // numero
                  ufConselhoFederal = value;
                } else if (oid.startsWith(item.getPrefix() + ConstantesIcp.SUFFIX_OID_CONSELHO_ESPECIALIDADE)) {
                  // numero
                  especialidadeConselhoFederal = value;
                }
              }
            }
          }
        } else if (id == GeneralName.rfc822Name) {
          Object obj = list.get(1);
          email = Asn1Objects.toString(obj, ConstantesIcp.DEFAULT_CHARSET);
        } else if (id == GeneralName.dNSName) {
          Object obj = list.get(1);
          dominio = Asn1Objects.toString(obj, ConstantesIcp.DEFAULT_CHARSET);
        }
      }
      tipoFormato = IcpBrasilHelper.getTipoFormato(certificate);
      if ((tipoConselhoFederal != null) && (numeroConselhoFederal != null) && (ufConselhoFederal != null) && (especialidadeConselhoFederal != null)) {
        dadoConselhoFederal = new DadoConselhoFederal(numeroConselhoFederal, ufConselhoFederal, especialidadeConselhoFederal, tipoConselhoFederal);
      }
      
      if ((tipoPessoa == TipoPessoa.PESSOA_FISICA) && (dadoPessoa != null)) {
        CertificadoPf certPF = new CertificadoPf(certificate);
        certPF.setCei(ceiPf);
        certPF.setDadoConselhoFederal(dadoConselhoFederal);
        certPF.setDadoPessoa(dadoPessoa);
        certPF.setDominio(dominio);
        certPF.setEmail(email);
        certPF.setNomeSocial(nomeSocial);
        certPF.setRegistroOab(registroOabPf);
        certPF.setRegistroSigepe(registroSigepe);
        certPF.setRegistroSincor(registroSincorPf);
        certPF.setRic(ricPf);
        certPF.setTipoFormato(tipoFormato);
        certPF.setTipoPessoa(tipoPessoa);
        certPF.setTituloEleitor(tituloEleitorPf);
        certificadoICPBrasil = certPF;
      } else if ((tipoPessoa == TipoPessoa.PESSOA_JURIDICA) && (dadoPessoa != null)) {
        CertificadoPj certPJ = new CertificadoPj(certificate);
        certPJ.setCei(ceiPj);
        certPJ.setCnpj(cnpjPj);
        certPJ.setDadoPessoa(dadoPessoa);
        certPJ.setDominio(dominio);
        certPJ.setEmail(email);
        certPJ.setNomeEmpresarial(nomeEmpresarialPj);
        certPJ.setResponsavel(responsavelPj);
        certPJ.setTipoFormato(tipoFormato);
        certPJ.setTipoPessoa(tipoPessoa);
        certificadoICPBrasil = certPJ;
      } else {
        certificadoICPBrasil = new CertificadoDesconhecido(certificate);
        certificadoICPBrasil.setDominio(dominio);
        certificadoICPBrasil.setEmail(email);
      }
    } else {
      certificadoICPBrasil = new CertificadoDesconhecido(certificate);
    }
    return certificadoICPBrasil;
  }

  private static TipoFormato getTipoFormato(final X509Certificate certificate) throws IOException {
    TipoFormato tipoFormato = TipoFormato.DESCONHECIDO;
    byte[] policiesBytes = certificate.getExtensionValue(Extension.certificatePolicies.getId());
    if (policiesBytes != null) {
      DEROctetString string = (DEROctetString) Asn1Objects.toAsn1Primitive(policiesBytes);
      byte[] octets = string.getOctets();
      ASN1Sequence sequence = Asn1Objects.toAsn1Sequence(octets);
      PolicyInformation information = PolicyInformation.getInstance(sequence.getObjectAt(0));
      ASN1ObjectIdentifier identifier = information.getPolicyIdentifier();
      String oid = identifier.getId();
      if (oid.startsWith(ConstantesIcp.PREFIX_OID_A1)) {
        tipoFormato = TipoFormato.A1;
      } else if (oid.startsWith(ConstantesIcp.PREFIX_OID_A2)) {
        tipoFormato = TipoFormato.A2;
      } else if (oid.startsWith(ConstantesIcp.PREFIX_OID_A3)) {
        tipoFormato = TipoFormato.A3;
      } else if (oid.startsWith(ConstantesIcp.PREFIX_OID_A4)) {
        tipoFormato = TipoFormato.A4;
      } else if (oid.startsWith(ConstantesIcp.PREFIX_OID_S1)) {
        tipoFormato = TipoFormato.S1;
      } else if (oid.startsWith(ConstantesIcp.PREFIX_OID_S2)) {
        tipoFormato = TipoFormato.S2;
      } else if (oid.startsWith(ConstantesIcp.PREFIX_OID_S3)) {
        tipoFormato = TipoFormato.S3;
      } else if (oid.startsWith(ConstantesIcp.PREFIX_OID_S4)) {
        tipoFormato = TipoFormato.S4;
      } else if (oid.startsWith(ConstantesIcp.PREFIX_OID_T3)) {
        tipoFormato = TipoFormato.T3;
      } else if (oid.startsWith(ConstantesIcp.PREFIX_OID_T4)) {
        tipoFormato = TipoFormato.T4;
      }
    }
    return tipoFormato;
  }

  private static String rpad(final String value, final char pad, final int size) {
    if (value.length() > size) {
      return value.substring(0, size);
    }
    StringBuilder builder = new StringBuilder();
    builder.append(value);
    while (builder.length() < size) {
      builder.append(pad);
    }
    return builder.toString();
  }

  private static String lpad(final String value, final char pad, final int size) {
    if (value.length() > size) {
      return value.substring(0, size);
    }
    String str = value;
    while (str.length() < size) {
      str = pad + str;
    }
    return str;
  }
}
