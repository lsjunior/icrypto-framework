package com.github.lsjunior.icrypto.core.signature.pades;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Array;
import java.security.cert.Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.esf.RevocationValues;

import com.github.lsjunior.icrypto.ICryptoException;
import com.github.lsjunior.icrypto.ICryptoLog;
import com.github.lsjunior.icrypto.api.model.CertificateRevocationData;
import com.github.lsjunior.icrypto.core.crl.CrlProvider;
import com.github.lsjunior.icrypto.core.crl.impl.SimpleCrlProvider;
import com.github.lsjunior.icrypto.core.ocsp.OcspProvider;
import com.github.lsjunior.icrypto.core.ocsp.impl.SimpleOcspProvider;
import com.github.lsjunior.icrypto.core.signature.cms.CadesService;
import com.github.lsjunior.icrypto.core.signature.cms.CadesServiceHelper;
import com.github.lsjunior.icrypto.core.signature.cms.CadesSignature;
import com.github.lsjunior.icrypto.core.signature.cms.CadesSignatureParameters;
import com.google.common.io.Files;

public class CadesSignatureAdapter {

  // https://www.adobe.com/devnet-docs/acrobatetk/tools/DigSig/oids.html
  private static final String ADBE_REVOCATION_INFO_ARCHIVAL = "1.2.840.113583.1.1.8";

  private PadesSignatureParameters parameters;

  public CadesSignatureAdapter(final PadesSignatureParameters parameters) {
    super();
    this.parameters = parameters;
  }

  public int doPreSign() throws IOException {
    if (this.parameters.isAddAdbeRevocationArchivalSignedAttribute()) {
      try {
        CrlProvider crlProvider = this.parameters.getCrlProvider();
        OcspProvider ocspProvider = this.parameters.getOcspProvider();

        if (crlProvider == null) {
          crlProvider = new SimpleCrlProvider();
        }
        if (ocspProvider == null) {
          ocspProvider = new SimpleOcspProvider();
        }

        List<Certificate> chain = this.parameters.getIdentity().getChain();
        Map<Certificate, CertificateRevocationData> revocations = CadesServiceHelper.getCrlAndOcsps(chain, crlProvider, ocspProvider);

        RevocationValues revocationValues = CadesServiceHelper.toRevocationValues(chain, revocations, true);
        ASN1ObjectIdentifier attributeId = new ASN1ObjectIdentifier(CadesSignatureAdapter.ADBE_REVOCATION_INFO_ARCHIVAL);
        DERSet attributeValue = new DERSet(revocationValues);

        Map<String, byte[]> signedAttributes = new HashMap<>();
        signedAttributes.put(attributeId.getId(), attributeValue.getEncoded());

        this.parameters.setRevocations(revocations);
        this.parameters.setSignedAttributes(signedAttributes);

        return signedAttributes.values().stream().mapToInt(Array::getLength).sum();
      } catch (Exception e) {
        throw new IOException(e);
      }
    }
    return 0;
  }

  public CadesSignature doSign(final InputStream content) throws IOException {
    ICryptoLog.getLogger().info("CadesSignatureInterface.sign()");
    File file = File.createTempFile("pades-2-cades", ".pdf");
    try {
      Files.asByteSink(file).writeFrom(content);
      //String hash = Files.asByteSource(file).hash(Hashing.sha256()).toString();
      //ICryptoLog.getLogger().debug("CadesSignatureInterface.hash " + hash);
      CadesSignatureParameters parameters = new CadesSignatureParameters();
      parameters.setAlgorithm(this.parameters.getAlgorithm());
      parameters.setCertPathProvider(this.parameters.getCertPathProvider());
      parameters.setCommitmentType(this.parameters.getCommitmentType());
      parameters.setContentName(this.parameters.getContentName());
      parameters.setContentTimeStamp(this.parameters.getContentTimeStamp());
      parameters.setContentType(this.parameters.getContentType());
      parameters.setCrlProvider(this.parameters.getCrlProvider());
      parameters.setOcspProvider(this.parameters.getOcspProvider());
      parameters.setData(Files.asByteSource(file));
      parameters.setDataDigested(false);
      parameters.setDetached(true);
      parameters.setDate(this.parameters.getDate());
      parameters.setDigestProvider(this.parameters.getDigestProvider());
      parameters.setIdentity(this.parameters.getIdentity());
      parameters.setIgnoreSigningTime(this.parameters.isIgnoreSigningTime());
      parameters.setLocation(this.parameters.getLocation());
      parameters.setProvider(this.parameters.getProvider());
      parameters.setSignatureProfile(this.parameters.getSignatureProfile());
      parameters.setSignatureId(this.parameters.getSignatureId());
      parameters.setSignaturePolicy(this.parameters.getSignaturePolicy());
      parameters.setSignatureProvider(this.parameters.getSignatureProvider());
      parameters.setTimeStampProvider(this.parameters.getTimeStampProvider());

      parameters.setRevocations(this.parameters.getRevocations());
      parameters.setSignedAttributes(this.parameters.getSignedAttributes());

      CadesService cadesService = CadesService.getInstance();
      CadesSignature signature = cadesService.sign(parameters);
      return signature;
    } catch (ICryptoException e) {
      throw e;
    } catch (Exception e) {
      throw new IOException(e);
    } finally {
      if (file.exists()) {
        file.delete();
      }
    }
  }

}
