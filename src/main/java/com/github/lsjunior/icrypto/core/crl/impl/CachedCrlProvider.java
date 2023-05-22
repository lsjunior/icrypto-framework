package com.github.lsjunior.icrypto.core.crl.impl;

import java.io.File;
import java.nio.charset.Charset;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Collection;
import java.util.Date;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.ICryptoException;
import com.github.lsjunior.icrypto.ICryptoLog;
import com.github.lsjunior.icrypto.core.crl.util.Crls;
import com.google.common.base.Joiner;
import com.google.common.hash.Hashing;
import com.google.common.io.Files;

public class CachedCrlProvider extends SimpleCrlProvider {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private File dir;

  public CachedCrlProvider() {
    super();
    File home = new File(System.getProperty("user.home"));
    this.dir = new File(home, ".icrypto-crls");
    if (!this.dir.exists()) {
      this.dir.mkdirs();
    }
  }

  @Override
  public byte[] getCrl(final Certificate certificate) {
    try {
      Collection<String> urls = Crls.getCrlUrlsAsString(certificate);
      String url = Joiner.on('|').join(urls);
      String hash = Hashing.sha256().hashString(url, Charset.defaultCharset()).toString();

      File file = new File(this.dir, hash);
      byte[] bytes = null;
      if (file.exists()) {
        ICryptoLog.getLogger().info("CRL File found " + file.getAbsolutePath());
        LocalDateTime localDateTime = LocalDateTime.now().plusMinutes(1);
        Date date = Date.from(localDateTime.atZone(ZoneId.systemDefault()).toInstant());
        X509CRL crl = (X509CRL) Crls.toCrl(Files.toByteArray(file));
        if (crl.getNextUpdate().after(date)) {
          ICryptoLog.getLogger().info("CRL File valid " + crl.getNextUpdate());
          bytes = crl.getEncoded();
        }
      }

      if (bytes == null) {
        bytes = super.getCrl(certificate);
        if (bytes != null) {
          ICryptoLog.getLogger().info("CRL File update " + file.getAbsolutePath());
          Files.write(bytes, file);
        } else {
          if (file.exists()) {
            file.delete();
          }
        }
      }
      return bytes;
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }

}
