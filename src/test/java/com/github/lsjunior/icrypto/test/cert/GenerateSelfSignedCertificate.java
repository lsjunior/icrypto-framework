package com.github.lsjunior.icrypto.test.cert;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.Collections;

import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.x500.X500Name;
import org.junit.jupiter.api.Test;

import com.github.lsjunior.icrypto.api.model.AlternativeNameType;
import com.github.lsjunior.icrypto.api.model.DistinguishedName;
import com.github.lsjunior.icrypto.api.model.SubjectAlternativeName;
import com.github.lsjunior.icrypto.api.type.ExtendedKeyUsageType;
import com.github.lsjunior.icrypto.api.type.KeyStoreType;
import com.github.lsjunior.icrypto.api.type.KeyUsageType;
import com.github.lsjunior.icrypto.core.Identity;
import com.github.lsjunior.icrypto.core.certificate.CertificateParameters;
import com.github.lsjunior.icrypto.core.certificate.CertificateService;
import com.github.lsjunior.icrypto.core.certificate.impl.CertificateServiceImpl;
import com.github.lsjunior.icrypto.core.certificate.util.Certificates;
import com.github.lsjunior.icrypto.core.store.impl.JcaStore;

public class GenerateSelfSignedCertificate {

  private static final String DNS_NAME = "lidersis.com.br";

  private static final String ALIAS = "lidersis";

  private static final String PASSWORD = "lidersis";

  private File createPkcs12File() throws Exception {
    SubjectAlternativeName subjectAlternativeName = new SubjectAlternativeName(GenerateSelfSignedCertificate.DNS_NAME, AlternativeNameType.DNS_NAME);

    DistinguishedName distinguishedName = new DistinguishedName("BR", "Lidersis", "Dev", GenerateSelfSignedCertificate.DNS_NAME);
    CertificateParameters certificateParameters = new CertificateParameters(distinguishedName);
    certificateParameters.setAlternativeNames(Collections.singleton(subjectAlternativeName));
    certificateParameters.setNotAfter(LocalDateTime.now().plusYears(3));
    certificateParameters.setNotBefore(LocalDateTime.now());

    certificateParameters.getKeyUsage().add(KeyUsageType.DIGITAL_SIGNATURE);
    certificateParameters.getKeyUsage().add(KeyUsageType.KEY_ENCIPHERMENT);
    certificateParameters.getKeyUsage().add(KeyUsageType.DATA_ENCIPHERMENT);
    certificateParameters.getExtendedKeyUsage().add(ExtendedKeyUsageType.CLIENT_AUTH);
    certificateParameters.getExtendedKeyUsage().add(ExtendedKeyUsageType.SERVER_AUTH);
    certificateParameters.setExtendedKeyUsageCritical(false);

    CertificateService certificateService = CertificateServiceImpl.getInstance();
    Identity identity = certificateService.generate(certificateParameters);

    File tmpFile = File.createTempFile(GenerateSelfSignedCertificate.ALIAS, ".p12");
    tmpFile.deleteOnExit();

    OutputStream outputStream = new FileOutputStream(tmpFile);

    JcaStore jcaStore = new JcaStore(KeyStoreType.PKCS12);
    jcaStore.add(GenerateSelfSignedCertificate.ALIAS, GenerateSelfSignedCertificate.PASSWORD, identity);
    jcaStore.write(outputStream, GenerateSelfSignedCertificate.PASSWORD);
    outputStream.close();

    return tmpFile;
  }

  private void checkFile(final File file) throws Exception {
    InputStream inputStream = new FileInputStream(file);
    JcaStore jcaStore = JcaStore.read(inputStream, GenerateSelfSignedCertificate.PASSWORD, KeyStoreType.PKCS12);
    assertTrue(jcaStore.getAliases().contains(GenerateSelfSignedCertificate.ALIAS));

    Identity identity = jcaStore.getIdentity(ALIAS, PASSWORD);
    assertNotNull(identity);

    X509Certificate x509Certificate = (X509Certificate) identity.getChain().get(0);
    X500Name x500Name = Certificates.toX500Name(x509Certificate.getSubjectX500Principal());
    assertEquals(DNS_NAME, ASN1UTF8String.getInstance(x500Name.getRDNs()[3].getFirst().getValue()).toString());
  }

  @Test
  void testCreateSelfSignedHttps() throws Exception {
    this.checkFile(this.createPkcs12File());
  }
}
