package com.github.lsjunior.icrypto.core.certificate.impl;

import java.io.OutputStream;
import java.io.Serializable;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.ICryptoException;
import com.github.lsjunior.icrypto.core.certificate.CertificateWriter;
import com.github.lsjunior.icrypto.core.certificate.util.Certificates;

public class Pkcs7CertificateWriter implements CertificateWriter, Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private static final Pkcs7CertificateWriter INSTANCE = new Pkcs7CertificateWriter();

  private Pkcs7CertificateWriter() {
    super();
  }

  public void write(final Collection<List<Certificate>> collection, final OutputStream outputStream) {
    try {
      CMSSignedDataGenerator signedDataGenerator = new CMSSignedDataGenerator();
      CMSTypedData content = new CMSAbsentContent();
      for (List<Certificate> chain : collection) {
        signedDataGenerator.addCertificates(Certificates.toStore(chain));
      }
      CMSSignedData signedData = signedDataGenerator.generate(content, false);
      byte[] bytes = signedData.getEncoded();
      outputStream.write(bytes);
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }

  @Override
  public void write(final List<Certificate> chain, final OutputStream outputStream) {
    this.write(Collections.singleton(chain), outputStream);
  }

  public static Pkcs7CertificateWriter getInstance() {
    return Pkcs7CertificateWriter.INSTANCE;
  }
}
