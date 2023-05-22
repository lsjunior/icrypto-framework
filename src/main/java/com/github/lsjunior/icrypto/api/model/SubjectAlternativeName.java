package com.github.lsjunior.icrypto.api.model;

import java.io.Serializable;

import com.github.lsjunior.icrypto.ICryptoConstants;

public class SubjectAlternativeName implements Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private String id;

  private String value;

  private AlternativeNameType type;

  public SubjectAlternativeName() {
    super();
  }

  public SubjectAlternativeName(final String value, final AlternativeNameType type) {
    super();
    this.value = value;
    this.type = type;
  }

  public SubjectAlternativeName(final String id, final String value, final AlternativeNameType type) {
    super();
    this.id = id;
    this.value = value;
    this.type = type;
  }

  public String getId() {
    return this.id;
  }

  public void setId(final String id) {
    this.id = id;
  }

  public String getValue() {
    return this.value;
  }

  public void setValue(final String value) {
    this.value = value;
  }

  public AlternativeNameType getType() {
    return this.type;
  }

  public void setType(final AlternativeNameType type) {
    this.type = type;
  }

}
