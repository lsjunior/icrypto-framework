package com.github.lsjunior.icrypto.core.ocsp.util;

import java.io.IOException;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.operator.OperatorCreationException;

import com.github.lsjunior.icrypto.ICryptoLog;
import com.github.lsjunior.icrypto.api.type.RevokeReasonType;
import com.github.lsjunior.icrypto.core.certificate.util.Certificates;
import com.github.lsjunior.icrypto.core.net.JdkWebClient;
import com.github.lsjunior.icrypto.core.net.WebClient;
import com.github.lsjunior.icrypto.core.util.Asn1Objects;

public abstract class Ocsps {

  private static final String CONTENT_TYPE_PROPERTY = "Content-Type";

  private static final String CONTENT_TYPE_VALUE = "application/ocsp-request";

  private static final String CONTENT_TRANSFER_ENCODING_PROPERTY = "Content-Transfer-Encoding";

  private static final String CONTENT_TRANSFER_ENCODING_BINARY = "binary";

  private static final WebClient WEB_CLIENT = new JdkWebClient();

  private Ocsps() {
    //
  }

  public static RevokeReasonType isRevoked(final byte[] ocsp) {
    BasicOCSPResponse basicOcspResponse = BasicOCSPResponse.getInstance(ocsp);
    BasicOCSPResp basicOcspResp = new BasicOCSPResp(basicOcspResponse);
    return Ocsps.isRevoked(basicOcspResp);
  }

  public static RevokeReasonType isRevoked(final BasicOCSPResp basicOcspResp) {
    SingleResp[] singleResps = basicOcspResp.getResponses();
    for (SingleResp singleResp : singleResps) {
      CertificateStatus certificateStatus = singleResp.getCertStatus();
      if (certificateStatus != null) {
        RevokeReasonType revokeReason = null;

        if (certificateStatus instanceof RevokedStatus) {
          RevokedStatus revokedStatus = (RevokedStatus) certificateStatus;
          revokeReason = RevokeReasonType.get(revokedStatus.getRevocationReason());
        }

        if (revokeReason == null) {
          revokeReason = RevokeReasonType.UNSPECIFIED;
        }

        return revokeReason;
      }
    }
    return null;
  }

  public static Collection<String> getOcspUrlsAsString(final Certificate certificate) throws IOException {
    X509Certificate x509Certificate = (X509Certificate) certificate;
    byte[] bytes = x509Certificate.getExtensionValue(Extension.authorityInfoAccess.getId());

    if (bytes == null) {
      return Collections.emptyList();
    }

    Set<String> urls = new HashSet<>();
    DEROctetString octetString = (DEROctetString) Asn1Objects.toAsn1Primitive(bytes);
    ASN1Sequence sequence = (ASN1Sequence) Asn1Objects.toAsn1Primitive(octetString.getOctets());
    AuthorityInformationAccess informationAccess = AuthorityInformationAccess.getInstance(sequence);
    AccessDescription[] accessDescriptions = informationAccess.getAccessDescriptions();

    String ocspId = OCSPObjectIdentifiers.id_pkix_ocsp.getId();

    for (AccessDescription description : accessDescriptions) {
      String currentId = description.getAccessMethod().getId();
      if (ocspId.equals(currentId)) {
        GeneralName generalName = description.getAccessLocation();
        ASN1TaggedObject taggedObject = (ASN1TaggedObject) generalName.toASN1Primitive();
        ASN1IA5String ia5String = ASN1IA5String.getInstance(taggedObject.getBaseObject());
        String urlStr = ia5String.getString();
        urls.add(urlStr);
      }
    }

    return urls;
  }

  public static Collection<URL> getOcspUrls(final Certificate certificate) throws IOException {
    Set<URL> urls = new HashSet<>();
    Collection<String> urlStrs = Ocsps.getOcspUrlsAsString(certificate);
    for (String urlStr : urlStrs) {
      try {
        URL url = new URL(urlStr);
        urls.add(url);
      } catch (MalformedURLException e) {
        ICryptoLog.getLogger().debug(e.getMessage(), e);
        ICryptoLog.getLogger().info("Invalid URL: " + urlStr);
      }
    }
    return urls;
  }

  public static Collection<OCSPResp> getOcsps(final X509Certificate certificate, final X509Certificate issuer) throws IOException {
    Collection<URL> urls = Ocsps.getOcspUrls(certificate);
    Collection<OCSPResp> ocsps = new ArrayList<>();
    if (urls != null) {
      for (URL url : urls) {
        try {
          OCSPResp ocspResp = Ocsps.getOcsp(certificate, issuer, url);
          ocsps.add(ocspResp);
        } catch (Exception e) {
          ICryptoLog.getLogger().info(e.getMessage(), e);
        }
      }
    }
    return ocsps;
  }

  public static OCSPResp getOcsp(final Certificate certificate, final Certificate issuer) throws IOException {
    X509Certificate x509Certificate = (X509Certificate) certificate;
    X509Certificate x509Issuer = (X509Certificate) issuer;
    return Ocsps.getOcsp(x509Certificate, x509Issuer);
  }

  public static OCSPResp getOcsp(final X509Certificate certificate, final X509Certificate issuer) throws IOException {
    Collection<URL> urls = Ocsps.getOcspUrls(certificate);
    if (urls != null) {
      for (URL url : urls) {
        try {
          OCSPResp ocspResp = Ocsps.getOcsp(certificate, issuer, url);
          if ((ocspResp != null) && (ocspResp.getStatus() == OCSPResponseStatus.SUCCESSFUL) && (ocspResp.getResponseObject() != null)) {
            return ocspResp;
          }
        } catch (Exception e) {
          ICryptoLog.getLogger().info(e.getMessage(), e);
        }
      }
    }
    return null;
  }

  public static OCSPResp getOcsp(final Certificate certificate, final Certificate issuer, final URL url) throws GeneralSecurityException, IOException, OperatorCreationException, OCSPException {
    X509Certificate x509Certificate = (X509Certificate) certificate;
    X509Certificate x509Issuer = (X509Certificate) issuer;
    return Ocsps.getOcsp(x509Certificate, x509Issuer, url);
  }

  public static OCSPResp getOcsp(final X509Certificate certificate, final X509Certificate issuer, final URL url) throws GeneralSecurityException, IOException, OperatorCreationException, OCSPException {
    OCSPReq req = Ocsps.getRequest(certificate, issuer);
    return Ocsps.getOcsp(req, url);
  }

  public static OCSPResp getOcsp(final OCSPReq request, final URL url) throws IOException {
    Map<String, String> properties = new HashMap<>();
    properties.put(Ocsps.CONTENT_TYPE_PROPERTY, Ocsps.CONTENT_TYPE_VALUE);
    properties.put(Ocsps.CONTENT_TRANSFER_ENCODING_PROPERTY, Ocsps.CONTENT_TRANSFER_ENCODING_BINARY);

    byte[] requestBytes = request.getEncoded();
    byte[] bytes = Ocsps.WEB_CLIENT.execute(url.toExternalForm(), requestBytes, properties);

    OCSPResp resp = new OCSPResp(bytes);
    return resp;
  }

  public static OCSPReq getRequest(final Certificate certificate, final Certificate issuer) throws GeneralSecurityException, IOException, OperatorCreationException, OCSPException {
    X509Certificate x509Certificate = (X509Certificate) certificate;
    X509Certificate x509Issuer = (X509Certificate) issuer;
    return Ocsps.getRequest(x509Certificate, x509Issuer);
  }

  public static OCSPReq getRequest(final X509Certificate certificate, final X509Certificate issuer) throws GeneralSecurityException, IOException, OperatorCreationException, OCSPException {
    BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
    return Ocsps.getRequest(certificate, issuer, nonce);
  }

  public static OCSPReq getRequest(final X509Certificate certificate, final X509Certificate issuer, final BigInteger nonce) throws GeneralSecurityException, IOException, OperatorCreationException, OCSPException {
    CertificateID certificateId = Certificates.getCertificateId(certificate, issuer);
    OCSPReqBuilder builder = new OCSPReqBuilder();

    ASN1OctetString asn1Nonce = new DEROctetString(nonce.toByteArray());
    ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
    extensionsGenerator.addExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, asn1Nonce);
    Extensions extensions = extensionsGenerator.generate();

    builder.addRequest(certificateId, extensions);

    return builder.build();
  }

}
