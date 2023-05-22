package com.github.lsjunior.icrypto.core.crl.util;

import java.io.File;
import java.io.Serializable;
import java.net.URL;
import java.util.Date;
import java.util.concurrent.Semaphore;

import com.github.lsjunior.icrypto.ICryptoConstants;

class CrlData implements Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private URL url;

  private File file;

  private Date date;

  private Date nextUpdate;

  private Semaphore semaphore;

  public CrlData() {
    super();
  }

  public CrlData(final URL url, final Semaphore semaphore) {
    super();
    this.url = url;
    this.semaphore = semaphore;
  }

  public URL getUrl() {
    return this.url;
  }

  public void setUrl(final URL url) {
    this.url = url;
  }

  public File getFile() {
    return this.file;
  }

  public void setFile(final File file) {
    this.file = file;
  }

  public Date getDate() {
    return this.date;
  }

  public void setDate(final Date date) {
    this.date = date;
  }

  public Date getNextUpdate() {
    return this.nextUpdate;
  }

  public void setNextUpdate(final Date nextUpdate) {
    this.nextUpdate = nextUpdate;
  }

  public Semaphore getSemaphore() {
    return this.semaphore;
  }

  public void setSemaphore(final Semaphore semaphore) {
    this.semaphore = semaphore;
  }

  // Aux
  public boolean isValid() {
    if (this.file != null) {
      Date date = new Date();
      if (date.before(this.nextUpdate)) {
        return true;
      }
    }
    return false;
  }
}
