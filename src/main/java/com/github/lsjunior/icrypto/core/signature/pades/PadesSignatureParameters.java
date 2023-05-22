package com.github.lsjunior.icrypto.core.signature.pades;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.core.signature.cms.CadesSignatureParameters;

public class PadesSignatureParameters extends CadesSignatureParameters {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private String filter;

  private String subFilter;

  private String name;

  private String reason;

  private String contactInfo;

  private String productInfo;

  private String signatureFieldName;

  private boolean addAdbeRevocationArchivalSignedAttribute;

  private VisibleSignatureParameters visibleSignature;

  public PadesSignatureParameters() {
    super();
  }

  public String getFilter() {
    return this.filter;
  }

  public void setFilter(final String filter) {
    this.filter = filter;
  }

  public String getSubFilter() {
    return this.subFilter;
  }

  public void setSubFilter(final String subFilter) {
    this.subFilter = subFilter;
  }

  public String getName() {
    return this.name;
  }

  public void setName(final String name) {
    this.name = name;
  }

  public String getReason() {
    return this.reason;
  }

  public void setReason(final String reason) {
    this.reason = reason;
  }

  public String getContactInfo() {
    return this.contactInfo;
  }

  public void setContactInfo(final String contactInfo) {
    this.contactInfo = contactInfo;
  }

  public String getProductInfo() {
    return this.productInfo;
  }

  public void setProductInfo(final String productInfo) {
    this.productInfo = productInfo;
  }

  public String getSignatureFieldName() {
    return this.signatureFieldName;
  }

  public void setSignatureFieldName(final String signatureFieldName) {
    this.signatureFieldName = signatureFieldName;
  }

  public boolean isAddAdbeRevocationArchivalSignedAttribute() {
    return this.addAdbeRevocationArchivalSignedAttribute;
  }

  public void setAddAdbeRevocationArchivalSignedAttribute(final boolean addAdbeRevocationArchivalSignedAttribute) {
    this.addAdbeRevocationArchivalSignedAttribute = addAdbeRevocationArchivalSignedAttribute;
  }

  public VisibleSignatureParameters getVisibleSignature() {
    return this.visibleSignature;
  }

  public void setVisibleSignature(final VisibleSignatureParameters visibleSignature) {
    this.visibleSignature = visibleSignature;
  }

}
