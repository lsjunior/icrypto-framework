package com.github.lsjunior.icrypto.core.crl;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import com.github.lsjunior.icrypto.ICryptoConstants;

public class CrlParameters implements Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private BigInteger number;

  private Date thisUpdate;

  private Date nextUpdate;

  private byte[] oldCrl;

  private Set<CrlEntry> entries;

  public CrlParameters() {
    this(BigInteger.ONE, null, null);
  }

  public CrlParameters(final BigInteger number, final Date thisUpdate, final Date nextUpdate) {
    super();
    this.number = number;
    this.thisUpdate = thisUpdate;
    this.nextUpdate = nextUpdate;
    this.entries = new HashSet<>();
  }

  public BigInteger getNumber() {
    return this.number;
  }

  public void setNumber(final BigInteger number) {
    this.number = number;
  }

  public Date getThisUpdate() {
    return this.thisUpdate;
  }

  public void setThisUpdate(final Date thisUpdate) {
    this.thisUpdate = thisUpdate;
  }

  public Date getNextUpdate() {
    return this.nextUpdate;
  }

  public void setNextUpdate(final Date nextUpdate) {
    this.nextUpdate = nextUpdate;
  }

  public byte[] getOldCrl() {
    return this.oldCrl;
  }

  public void setOldCrl(final byte[] oldCrl) {
    this.oldCrl = oldCrl;
  }

  public Set<CrlEntry> getEntries() {
    return this.entries;
  }

  public void setEntries(final Set<CrlEntry> entries) {
    this.entries = entries;
  }

}
