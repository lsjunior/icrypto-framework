package com.github.lsjunior.icrypto.core.crl;

import java.io.Serializable;
import java.math.BigInteger;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

import com.github.lsjunior.icrypto.ICryptoConstants;

public class CrlParameters implements Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private BigInteger number;

  private LocalDateTime thisUpdate;

  private LocalDateTime nextUpdate;

  private byte[] oldCrl;

  private Set<CrlEntry> entries;

  public CrlParameters() {
    this(BigInteger.ONE, null, null);
  }

  public CrlParameters(final BigInteger number, final LocalDateTime thisUpdate, final LocalDateTime nextUpdate) {
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

  public LocalDateTime getThisUpdate() {
    return this.thisUpdate;
  }

  public void setThisUpdate(final LocalDateTime thisUpdate) {
    this.thisUpdate = thisUpdate;
  }

  public LocalDateTime getNextUpdate() {
    return this.nextUpdate;
  }

  public void setNextUpdate(final LocalDateTime nextUpdate) {
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
