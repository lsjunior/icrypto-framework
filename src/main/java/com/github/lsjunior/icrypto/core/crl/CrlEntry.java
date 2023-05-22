package com.github.lsjunior.icrypto.core.crl;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Date;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.api.type.RevokeReasonType;

public class CrlEntry implements Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private final BigInteger serialNumber;

  private final RevokeReasonType reason;

  private final Date date;

  public CrlEntry(final BigInteger serialNumber, final RevokeReasonType reason) {
    this(serialNumber, reason, new Date());
  }

  public CrlEntry(final BigInteger serialNumber, final RevokeReasonType reason, final Date date) {
    super();
    this.serialNumber = serialNumber;
    this.reason = reason;
    this.date = date;
  }

  public BigInteger getSerialNumber() {
    return this.serialNumber;
  }

  public RevokeReasonType getReason() {
    return this.reason;
  }

  public Date getDate() {
    return this.date;
  }

  @Override
  public int hashCode() {
    return this.serialNumber.hashCode();
  }

  @Override
  public boolean equals(final Object obj) {
    if (obj == null) {
      return false;
    }

    if (this == obj) {
      return true;
    }

    if (obj instanceof CrlEntry) {
      CrlEntry ce = (CrlEntry) obj;
      return this.getSerialNumber().equals(ce.getSerialNumber());
    }

    return false;
  }

}
