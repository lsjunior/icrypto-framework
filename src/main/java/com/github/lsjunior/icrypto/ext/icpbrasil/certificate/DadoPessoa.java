package com.github.lsjunior.icrypto.ext.icpbrasil.certificate;

import java.io.Serializable;
import java.util.Date;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.ICryptoException;
import com.google.common.base.Strings;

public class DadoPessoa implements Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private Date dataNascimento;

  private String cpf;

  private String pis;

  private String rg;

  private String emissorRg;

  public DadoPessoa() {
    super();
  }

  public DadoPessoa(final Date dataNascimento, final String cpf, final String pis, final String rg, final String emissorRg) {
    super();
    this.dataNascimento = dataNascimento;
    this.cpf = cpf;
    this.pis = pis;
    this.rg = rg;
    this.emissorRg = emissorRg;
  }

  public Date getDataNascimento() {
    return this.dataNascimento;
  }

  public void setDataNascimento(final Date dataNascimento) {
    this.dataNascimento = dataNascimento;
  }

  public String getCpf() {
    return this.cpf;
  }

  public void setCpf(final String cpf) {
    this.cpf = cpf;
  }

  public String getPis() {
    return this.pis;
  }

  public void setPis(final String pis) {
    this.pis = pis;
  }

  public String getRg() {
    return this.rg;
  }

  public void setRg(final String rg) {
    this.rg = rg;
  }

  public String getEmissorRg() {
    return this.emissorRg;
  }

  public void setEmissorRg(final String emissorRg) {
    this.emissorRg = emissorRg;
  }

  // Aux
  @Override
  public String toString() {
    return this.toOtherNameString();
  }

  public String toOtherNameString() {
    String dataNascimento = IcpBrasilHelper.getDateValue(this.getDataNascimento());
    String cpf = IcpBrasilHelper.getNumericValue(this.getCpf(), 11);
    String pis = IcpBrasilHelper.getNumericValue(this.getPis(), 11);
    String rg = IcpBrasilHelper.getNumericValue(this.getRg(), 15);
    String emissorRg = IcpBrasilHelper.getValue(this.getEmissorRg());

    String str = dataNascimento + cpf + pis + rg + emissorRg;
    return str;
  }

  // Static

  public static DadoPessoa getInstance(final String otherNameString) {
    try {
      if (Strings.isNullOrEmpty(otherNameString)) {
        return null;
      }

      String dataStr = otherNameString.substring(0, 8); // Data Nascimento
      Date data = null;
      String cpf = otherNameString.substring(8, 19); // CPF
      String pis = IcpBrasilHelper.getValueFromNumeric(otherNameString.substring(20, 30)); // PIS
      String rg = IcpBrasilHelper.getValueFromNumeric(otherNameString.substring(30, 45)); // Rg
      String emissorRg = otherNameString.substring(45).trim(); // Emissor Rg
      if ((!Strings.isNullOrEmpty(dataStr)) && (!Strings.isNullOrEmpty(dataStr.replaceAll("0", "")))) {
        data = IcpBrasilHelper.getDateFromString(dataStr);
      }

      if (Strings.isNullOrEmpty(cpf)) {
        cpf = null;
      }
      if (Strings.isNullOrEmpty(pis)) {
        pis = null;
      }
      if (Strings.isNullOrEmpty(rg)) {
        rg = null;
      }

      return new DadoPessoa(data, cpf, pis, rg, emissorRg);
    } catch (Exception e) {
      throw new ICryptoException(e);
    }

  }

}
