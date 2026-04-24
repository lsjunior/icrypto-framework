package com.github.lsjunior.icrypto.test.cert;

import java.io.File;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.github.lsjunior.icrypto.core.certificate.util.Certificates;
import com.github.lsjunior.icrypto.core.util.Asn1Objects;
import com.github.lsjunior.icrypto.ext.icpbrasil.certificate.CertificadoIcp;
import com.github.lsjunior.icrypto.ext.icpbrasil.certificate.CertificadoPf;
import com.google.common.io.Files;

public class CertificadoDrAuroTest {

  @Test
  void testCertDoct() throws Exception {
    File file = new File("src/test/resources/dr-auro.crt");
    this.printCert(file);
  }

  private void printCert(final File file) throws Exception {
    Certificate certificate = Certificates.toCertificate(Files.toByteArray(file));
    X509Certificate x509Certificate = (X509Certificate) certificate;
    CertificadoIcp certificadoIcp = CertificadoIcp.getInstance(x509Certificate);
    Assertions.assertNotNull(certificadoIcp);

    System.out.println(x509Certificate.getSerialNumber());
    System.out.println(x509Certificate.getCriticalExtensionOIDs());
    System.out.println(x509Certificate.getNonCriticalExtensionOIDs());
    System.out.println(certificadoIcp.getTipoPessoa());

    Assertions.assertInstanceOf(CertificadoPf.class, certificadoIcp);
    CertificadoPf certificadoPf = (CertificadoPf) certificadoIcp;

    System.out.println(certificadoPf.getCpf());
    System.out.println(certificadoPf.getDataNascimento());
    System.out.println(certificadoPf.getRg() + " / " + certificadoPf.getEmissorRg());
    System.out.println(certificadoPf.getTituloEleitor());
    System.out.println(certificadoPf.getDadoConselhoFederal());
  }

}
