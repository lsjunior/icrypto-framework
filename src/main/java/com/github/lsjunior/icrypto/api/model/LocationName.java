package com.github.lsjunior.icrypto.api.model;

import java.io.Serializable;

import com.github.lsjunior.icrypto.ICryptoConstants;

public class LocationName implements Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private String countryName;

  private String localityName;

  public LocationName() {
    super();
  }

  public LocationName(final String countryName, final String localityName) {
    super();
    this.countryName = countryName;
    this.localityName = localityName;
  }

  public String getCountryName() {
    return this.countryName;
  }

  public void setCountryName(final String countryName) {
    this.countryName = countryName;
  }

  public String getLocalityName() {
    return this.localityName;
  }

  public void setLocalityName(final String localityName) {
    this.localityName = localityName;
  }

  @Override
  public String toString() {
    return this.getLocalityName();
  }

}
