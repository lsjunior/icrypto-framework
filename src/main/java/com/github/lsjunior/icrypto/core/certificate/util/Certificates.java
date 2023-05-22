package com.github.lsjunior.icrypto.core.certificate.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.util.Store;

import com.github.lsjunior.icrypto.ICryptoException;
import com.github.lsjunior.icrypto.api.model.DistinguishedName;
import com.github.lsjunior.icrypto.api.model.LocationName;
import com.github.lsjunior.icrypto.api.type.CertificateType;
import com.github.lsjunior.icrypto.api.type.KeyUsageType;
import com.github.lsjunior.icrypto.core.util.Asn1Objects;
import com.github.lsjunior.icrypto.core.util.BcProvider;
import com.google.common.base.Strings;
import com.google.common.collect.Lists;
import com.google.common.hash.Hashing;

public abstract class Certificates {

  private Certificates() {
    //
  }

  public static List<Certificate> toCertificates(final InputStream inputStream) {
    if (inputStream == null) {
      return null;
    }
    try {
      CertificateFactory certFactory = CertificateFactory.getInstance(CertificateType.X509.getType());
      Collection<? extends Certificate> collection = certFactory.generateCertificates(inputStream);
      List<Certificate> list = Lists.newArrayList(collection);
      return list;
    } catch (GeneralSecurityException e) {
      throw new ICryptoException(e);
    }
  }

  public static List<Certificate> toCertificates(final byte[] bytes) {
    if (bytes == null) {
      return null;
    }
    InputStream inputStream = new ByteArrayInputStream(bytes);
    return Certificates.toCertificates(inputStream);
  }

  public static Certificate toCertificate(final InputStream inputStream) {
    if (inputStream == null) {
      return null;
    }
    try {
      CertificateFactory certFactory = CertificateFactory.getInstance(CertificateType.X509.getType());
      Certificate certificate = certFactory.generateCertificate(inputStream);
      return certificate;
    } catch (GeneralSecurityException e) {
      throw new ICryptoException(e);
    }
  }

  public static Certificate toCertificate(final byte[] bytes) {
    if (bytes == null) {
      return null;
    }
    InputStream inputStream = new ByteArrayInputStream(bytes);
    return Certificates.toCertificate(inputStream);
  }

  public static Map<String, Certificate> toCertificates(final ZipInputStream inputStream) throws IOException {
    Map<String, Certificate> certificates = new HashMap<>();

    ZipEntry entry = inputStream.getNextEntry();
    while (entry != null) {
      Certificate certificate = Certificates.toCertificate(inputStream);
      certificates.put(entry.getName(), certificate);
      entry = inputStream.getNextEntry();
    }

    return certificates;
  }

  public static byte[] toByteArray(final Certificate certificate) throws CertificateEncodingException {
    if (certificate != null) {
      return ((X509Certificate) certificate).getEncoded();
    }
    return null;
  }

  @SuppressWarnings("unused")
  public static boolean isSelfSigned(final Certificate certificate) throws GeneralSecurityException {
    try {
      PublicKey publicKey = certificate.getPublicKey();
      certificate.verify(publicKey);
      return true;
    } catch (SignatureException | InvalidKeyException | NoSuchAlgorithmException e) {
      // ICryptoLog.getLogger().debug(e.getMessage(), e);
      return false;
    }
  }

  public static boolean isCa(final Certificate certificate) {
    X509Certificate x509Certificate = (X509Certificate) certificate;
    int basic = x509Certificate.getBasicConstraints();
    boolean[] keyUsage = x509Certificate.getKeyUsage();
    if ((keyUsage != null) && (basic >= 0) && (keyUsage[KeyUsageType.KEY_CERT_SIGN.getIndex()])) {
      return true;
    }
    return false;
  }

  public static int getKeySize(final Certificate certificate) {
    if (certificate == null) {
      return -1;
    }
    PublicKey publicKey = certificate.getPublicKey();
    if (publicKey instanceof RSAKey) {
      RSAKey rsaKey = (RSAKey) publicKey;
      int keySize = rsaKey.getModulus().bitLength();
      return keySize;
    }
    return -1;
  }

  public static String getKeyAlgorithm(final Certificate certificate) {
    if (certificate == null) {
      return null;
    }
    PublicKey publicKey = certificate.getPublicKey();
    return publicKey.getAlgorithm();
  }

  // BC
  public static X509CertificateHolder toCertificateHolder(final Certificate certificate) throws CertificateEncodingException, IOException {
    return new X509CertificateHolder(Certificates.toByteArray(certificate));
  }

  public static List<X509CertificateHolder> toCertificateHolders(final Collection<Certificate> certificates) throws CertificateEncodingException, IOException {
    List<X509CertificateHolder> collection = new ArrayList<>();
    for (Certificate certificate : certificates) {
      collection.add(Certificates.toCertificateHolder(certificate));
    }
    return collection;
  }

  public static Certificate toCertificate(final X509CertificateHolder holder) throws CertificateException {
    JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
    converter.setProvider(BcProvider.PROVIDER_NAME);
    // BC Implementation causes errors on X509Structure
    // Converting do default
    Certificate x509Certificate = Certificates.toCertificate(Certificates.toByteArray(converter.getCertificate(holder)));
    return x509Certificate;
  }

  public static List<Certificate> toCertificates(final Collection<X509CertificateHolder> holders) throws CertificateException {
    List<Certificate> collection = new ArrayList<>();
    for (X509CertificateHolder holder : holders) {
      collection.add(Certificates.toCertificate(holder));
    }
    return collection;
  }

  public static List<Certificate> getChain(final X509CertificateHolder holder, final Collection<X509CertificateHolder> holders) throws GeneralSecurityException {
    if (holders != null) {
      Certificate certificate = Certificates.toCertificate(holder);
      List<Certificate> list = new ArrayList<>();
      for (X509CertificateHolder h : holders) {
        Certificate c = Certificates.toCertificate(h);
        list.add(c);
      }
      CertPath certPath = CertPaths.toCertPath(certificate, list);
      List<Certificate> chain = CertPaths.toCertificate(certPath);
      return chain;
    }
    Certificate c = Certificates.toCertificate(holder);
    return Collections.singletonList(c);
  }

  @SuppressWarnings("rawtypes")
  public static Store toStore(final Collection<Certificate> chain) throws CertificateEncodingException {
    JcaCertStore certStore = new JcaCertStore(chain);
    return certStore;
  }

  @SuppressWarnings("rawtypes")
  public static Store toStore(final Certificate certificate) throws CertificateEncodingException {
    JcaCertStore certStore = new JcaCertStore(Collections.singleton(certificate));
    return certStore;
  }

  public static String toString(final X500Principal principal) {
    if (principal == null) {
      return null;
    }

    X500Name x500Name = new X500Name(principal.getName());
    return Certificates.toString(x500Name);
  }

  public static String toString(final X500Name name) {
    if (name == null) {
      return null;
    }
    RDN[] rdns = name.getRDNs(BCStyle.CN);
    String s = null;
    if ((rdns != null) && (rdns.length > 0)) {
      s = IETFUtils.valueToString(rdns[0].getFirst().getValue());
    } else {
      s = name.toString();
    }
    return s;
  }

  public static X500Principal toX500Principal(final LocationName name) throws IOException {
    if (name == null) {
      return null;
    }
    X500Name x500Name = Certificates.toX500Name(name);
    return Certificates.toX500Principal(x500Name);
  }

  public static X500Principal toX500Principal(final DistinguishedName name) throws IOException {
    X500Name x500Name = Certificates.toX500Name(name);
    return Certificates.toX500Principal(x500Name);
  }

  public static X500Principal toX500Principal(final X500Name name) throws IOException {
    X500Principal principal = new X500Principal(name.getEncoded());
    return principal;
  }

  public static X500Name toX500Name(final LocationName name) {
    X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
    if (!Strings.isNullOrEmpty(name.getCountryName())) {
      builder.addRDN(BCStyle.C, name.getCountryName());
    }
    if (!Strings.isNullOrEmpty(name.getLocalityName())) {
      builder.addRDN(BCStyle.L, name.getLocalityName());
    }
    return builder.build();
  }

  public static X500Name toX500Name(final GeneralNames generalNames) {
    for (GeneralName generalName : generalNames.getNames()) {
      if (generalName.getTagNo() == GeneralName.directoryName) {
        X500Name x500Name = X500Name.getInstance(generalName.getName());
        return x500Name;
      }
    }
    return null;
  }

  public static X500Name toX500Name(final DistinguishedName name) {
    X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
    if (!Strings.isNullOrEmpty(name.getCountryName())) {
      builder.addRDN(BCStyle.C, name.getCountryName());
    }
    if (!Strings.isNullOrEmpty(name.getLocalityName())) {
      builder.addRDN(BCStyle.L, name.getLocalityName());
    }
    if (!Strings.isNullOrEmpty(name.getStateOrProvinceName())) {
      builder.addRDN(BCStyle.ST, name.getStateOrProvinceName());
    }
    if (!Strings.isNullOrEmpty(name.getStreetAddress())) {
      builder.addRDN(BCStyle.STREET, name.getStreetAddress());
    }
    if (!Strings.isNullOrEmpty(name.getOrganizationName())) {
      builder.addRDN(BCStyle.O, name.getOrganizationName());
    }
    if (!Strings.isNullOrEmpty(name.getOrganizationalUnitName())) {
      builder.addRDN(BCStyle.OU, name.getOrganizationalUnitName());
    }
    if (!Strings.isNullOrEmpty(name.getCommonName())) {
      builder.addRDN(BCStyle.CN, name.getCommonName());
    }
    return builder.build();
  }

  public static X500Name toX500Name(final X500Principal principal) {
    X500Name x500Name = X500Name.getInstance(principal.getEncoded());
    return x500Name;
  }

  public static LocationName toLocationName(final X500Name name) {
    LocationName locationName = new LocationName();
    for (RDN rdn : name.getRDNs()) {
      AttributeTypeAndValue attributeTypeAndValue = rdn.getFirst();
      if (attributeTypeAndValue.getType().getId().equals(BCStyle.C.getId())) {
        locationName.setCountryName(ASN1UTF8String.getInstance(attributeTypeAndValue.getValue()).getString());
      }
      if (attributeTypeAndValue.getType().getId().equals(BCStyle.L.getId())) {
        locationName.setLocalityName(ASN1UTF8String.getInstance(attributeTypeAndValue.getValue()).getString());
      }
    }
    return locationName;
  }

  public static DistinguishedName toDistinguishedName(final X500Name name) {
    DistinguishedName distinguishedName = new DistinguishedName();
    for (RDN rdn : name.getRDNs()) {
      AttributeTypeAndValue attributeTypeAndValue = rdn.getFirst();
      if (attributeTypeAndValue.getType().getId().equals(BCStyle.C.getId())) {
        distinguishedName.setCountryName(ASN1UTF8String.getInstance(attributeTypeAndValue.getValue()).getString());
      }
      if (attributeTypeAndValue.getType().getId().equals(BCStyle.L.getId())) {
        distinguishedName.setLocalityName(ASN1UTF8String.getInstance(attributeTypeAndValue.getValue()).getString());
      }
      if (attributeTypeAndValue.getType().getId().equals(BCStyle.ST.getId())) {
        distinguishedName.setStateOrProvinceName(ASN1UTF8String.getInstance(attributeTypeAndValue.getValue()).getString());
      }
      if (attributeTypeAndValue.getType().getId().equals(BCStyle.STREET.getId())) {
        distinguishedName.setStreetAddress(ASN1UTF8String.getInstance(attributeTypeAndValue.getValue()).getString());
      }
      if (attributeTypeAndValue.getType().getId().equals(BCStyle.O.getId())) {
        distinguishedName.setOrganizationName(ASN1UTF8String.getInstance(attributeTypeAndValue.getValue()).getString());
      }
      if (attributeTypeAndValue.getType().getId().equals(BCStyle.OU.getId())) {
        distinguishedName.setOrganizationalUnitName(ASN1UTF8String.getInstance(attributeTypeAndValue.getValue()).getString());
      }
      if (attributeTypeAndValue.getType().getId().equals(BCStyle.CN.getId())) {
        distinguishedName.setCommonName(ASN1UTF8String.getInstance(attributeTypeAndValue.getValue()).getString());
      }
    }
    return distinguishedName;
  }

  public static CertificateID getCertificateId(final Certificate certificate, final Certificate issuer) throws IOException, GeneralSecurityException, OperatorCreationException, OCSPException {
    X509Certificate x509Certificate = (X509Certificate) certificate;
    X509Certificate x509Issuer = (X509Certificate) issuer;
    return Certificates.getCertificateId(x509Certificate, x509Issuer);
  }

  public static CertificateID getCertificateId(final X509Certificate certificate, final X509Certificate issuer) throws IOException, GeneralSecurityException, OperatorCreationException, OCSPException {
    DigestCalculatorProvider provider = new BcDigestCalculatorProvider();
    AlgorithmIdentifier digestAlgorithmIdentifier = CertificateID.HASH_SHA1;
    DigestCalculator digestCalculator = provider.get(digestAlgorithmIdentifier);
    X509CertificateHolder holder = new X509CertificateHolder(issuer.getEncoded());
    BigInteger serialNumber = certificate.getSerialNumber();
    CertificateID certificateId = new CertificateID(digestCalculator, holder, serialNumber);
    return certificateId;
  }

  public static String getEmail(final Certificate certificate) throws CertificateParsingException {
    Collection<List<?>> alternativeNames = ((X509Certificate) certificate).getSubjectAlternativeNames();
    for (List<?> list : alternativeNames) {
      Integer tmp = (Integer) list.get(0);
      if ((tmp != null) && (tmp.intValue() == GeneralName.rfc822Name)) {
        Object obj = list.get(1);
        return Asn1Objects.toString(obj, Charset.defaultCharset());
      }
    }
    return null;
  }

  @SuppressWarnings("deprecation")
  public static String getThumbprint(final Certificate certificate) throws CertificateEncodingException {
    return Hashing.sha1().hashBytes(certificate.getEncoded()).toString();
  }

}
