package com.github.lsjunior.icrypto.api.model;

import com.github.lsjunior.icrypto.ICryptoConstants;

public class DistinguishedName extends LocationName {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private String stateOrProvinceName;

  private String streetAddress;

  private String organizationName;

  private String organizationalUnitName;

  private String commonName;

  public DistinguishedName() {
    super();
  }

  public DistinguishedName(final String commonName) {
    super();
    this.commonName = commonName;
  }

  public DistinguishedName(final String countryName, final String organizationName, final String organizationalUnitName, final String commonName) {
    super(countryName, null);
    this.organizationName = organizationName;
    this.organizationalUnitName = organizationalUnitName;
    this.commonName = commonName;
  }

  public String getStateOrProvinceName() {
    return this.stateOrProvinceName;
  }

  public void setStateOrProvinceName(final String stateOrProvinceName) {
    this.stateOrProvinceName = stateOrProvinceName;
  }

  public String getStreetAddress() {
    return this.streetAddress;
  }

  public void setStreetAddress(final String streetAddress) {
    this.streetAddress = streetAddress;
  }

  public String getOrganizationName() {
    return this.organizationName;
  }

  public void setOrganizationName(final String organizationName) {
    this.organizationName = organizationName;
  }

  public String getOrganizationalUnitName() {
    return this.organizationalUnitName;
  }

  public void setOrganizationalUnitName(final String organizationalUnitName) {
    this.organizationalUnitName = organizationalUnitName;
  }

  public String getCommonName() {
    return this.commonName;
  }

  public void setCommonName(final String commonName) {
    this.commonName = commonName;
  }

  @Override
  public String toString() {
    return this.getCommonName();
  }

}
