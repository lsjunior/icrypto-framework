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
import org.junit.jupiter.api.Test;

import com.github.lsjunior.icrypto.core.certificate.util.Certificates;
import com.github.lsjunior.icrypto.core.util.Asn1Objects;
import com.github.lsjunior.icrypto.ext.icpbrasil.certificate.CertificadoIcp;
import com.github.lsjunior.icrypto.ext.icpbrasil.certificate.CertificadoPf;
import com.google.common.io.Files;

public class CertificadoGovBrTest {

  @Test
  void testCertDoct() throws Exception {
    File file = new File("D:\\Trabalho\\Lidersis\\pki\\lourival-govbr.cer");
    this.printCert(file);
  }

  private void printCert(final File file) throws Exception {
    Certificate certificate = Certificates.toCertificate(Files.toByteArray(file));
    X509Certificate x509Certificate = (X509Certificate) certificate;
    CertificadoIcp certificadoIcp = CertificadoIcp.getInstance(x509Certificate);
    System.out.println(x509Certificate.getSerialNumber());
    System.out.println(x509Certificate.getCriticalExtensionOIDs());
    System.out.println(x509Certificate.getNonCriticalExtensionOIDs());
    System.out.println(certificadoIcp.getTipoPessoa());
    if (certificadoIcp instanceof CertificadoPf) {
      System.out.println(((CertificadoPf) certificadoIcp).getCpf());
    }
    System.out.println("=======================================================");

    X509CertificateHolder x509CertificateHolder = new X509CertificateHolder(certificate.getEncoded());
    Extension extension = x509CertificateHolder.getExtension(ASN1ObjectIdentifier.tryFromID("2.5.29.32"));
    System.out.println(extension);

    CertificatePolicies certificatePolicies = CertificatePolicies.getInstance(extension.getParsedValue());
    System.out.println(certificatePolicies);
    for (PolicyInformation policyInformation : certificatePolicies.getPolicyInformation()) {
      System.out.println("  " + policyInformation.getPolicyIdentifier() + " => " + policyInformation.getPolicyQualifiers());
      if (policyInformation.getPolicyQualifiers() != null) {
        for (int i = 0; i < policyInformation.getPolicyQualifiers().size(); i++) {
          ASN1Encodable obj = policyInformation.getPolicyQualifiers().getObjectAt(i);
          PolicyQualifierInfo policyQualifierInfo = PolicyQualifierInfo.getInstance(obj);
          System.out.println("    " + policyQualifierInfo.getPolicyQualifierId() + " => " + ASN1IA5String.getInstance(policyQualifierInfo.getQualifier()));
        }
      }
    }

    String str = Asn1Objects.dump(certificate.getEncoded(), true);
    System.out.println(str);
    // File out = new File(file.getParentFile(), file.getName() + ".txt");
    // Files.asCharSink(out, StandardCharsets.UTF_8).write(str);
  }

}
