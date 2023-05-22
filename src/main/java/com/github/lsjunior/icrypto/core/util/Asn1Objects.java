package com.github.lsjunior.icrypto.core.util;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.text.ParseException;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cms.DefaultCMSSignatureAlgorithmNameGenerator;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.SignatureAlgorithmIdentifierFinder;

import com.github.lsjunior.icrypto.ICryptoLog;
import com.github.lsjunior.icrypto.api.type.DigestType;
import com.github.lsjunior.icrypto.api.type.SignatureType;
import com.google.common.base.Strings;

public abstract class Asn1Objects {

  private Asn1Objects() {
    //
  }

  public static ASN1Object toASN1Object(final ASN1Encodable obj) {
    if (obj == null) {
      return null;
    }
    if (obj instanceof ASN1TaggedObject) {
      ASN1TaggedObject to = (ASN1TaggedObject) obj;
      return to.toASN1Primitive();
    }
    return obj.toASN1Primitive();
  }

  public static ASN1Encodable getObjectAt(final ASN1Sequence sequence, final int index) {
    if (sequence == null) {
      return null;
    }
    int size = sequence.size();
    if ((size == 0) || (size <= index)) {
      return null;
    }
    return sequence.getObjectAt(index);
  }

  public static ASN1Sequence toAsn1Sequence(final ASN1Encodable... objects) {
    ASN1EncodableVector v = new ASN1EncodableVector();
    for (ASN1Encodable o : objects) {
      if (o != null) {
        v.add(o);
      }
    }
    return new DERSequence(v);
  }

  public static ASN1Sequence toAsn1Sequence(final byte[] bytes) throws IOException {
    ASN1Primitive primitive = Asn1Objects.toAsn1Primitive(bytes);
    ASN1Sequence sequence = (ASN1Sequence) primitive;
    return sequence;
  }

  public static ASN1IA5String toAsn1Ia5String(final ASN1Encodable obj) {
    if (obj == null) {
      return null;
    }
    if (obj instanceof ASN1TaggedObject) {
      ASN1TaggedObject to = (ASN1TaggedObject) obj;
      return ASN1IA5String.getInstance(to, false);
    }
    return ASN1IA5String.getInstance(obj);
  }

  public static ASN1TaggedObject toAsn1TaggedObject(final ASN1Encodable obj, final int tagNo) {
    if (obj == null) {
      return null;
    }
    return new DERTaggedObject(tagNo, obj);
  }

  public static ASN1Primitive toAsn1Primitive(final ASN1OctetString octetString) throws IOException {
    ASN1Primitive obj = ASN1Primitive.fromByteArray(octetString.getOctets());
    return obj;
  }

  public static ASN1Primitive toAsn1Primitive(final byte[] bytes) throws IOException {
    ASN1Primitive obj = ASN1Primitive.fromByteArray(bytes);
    return obj;
  }

  public static BigInteger toBigInteger(final ASN1Integer integer) {
    if (integer != null) {
      return integer.getValue();
    }
    return null;
  }

  public static Date toDate(final Time time) {
    if (time != null) {
      return time.getDate();
    }
    return null;
  }

  public static Date toDate(final ASN1GeneralizedTime time) throws ParseException {
    if (time != null) {
      return time.getDate();
    }
    return null;
  }

  public static Date toDate(final ASN1UTCTime time) throws ParseException {
    if (time != null) {
      return time.getDate();
    }
    return null;
  }

  public static String toString(final ASN1TaggedObject tag) {
    ASN1Primitive obj = tag.toASN1Primitive();
    return Asn1Objects.toString(obj, Charset.defaultCharset());
  }

  public static String toString(final ASN1TaggedObject tag, final Charset charset) {
    ASN1Primitive obj = tag.toASN1Primitive();
    return Asn1Objects.toString(obj, charset);
  }

  public static String toString(final Object obj, final Charset charset) {
    if (obj == null) {
      return null;
    }
    if (obj instanceof String) {
      return (String) obj;
    }
    if (obj instanceof ASN1String) {
      return ((ASN1String) obj).getString();
    }
    if (obj instanceof ASN1OctetString) {
      return new String(((ASN1OctetString) obj).getOctets(), charset);
    }
    ICryptoLog.getLogger().warn("Unknow value (" + obj.getClass() + ") " + obj);
    return null;
  }

  public static String dump(final byte[] bytes, final boolean verbose) throws IOException {
    ASN1Primitive object = Asn1Objects.toAsn1Primitive(bytes);
    return Asn1Objects.dump(object, verbose);
  }

  public static String dump(final ASN1Primitive obj, final boolean verbose) {
    return ASN1Dump.dumpAsString(obj, verbose);
  }

  // Digest
  public static AlgorithmIdentifier getAlgorithmIdentifier(final DigestType digestType) {
    DigestAlgorithmIdentifierFinder digestAlgorithmIdentifierFinder = new DefaultDigestAlgorithmIdentifierFinder();
    AlgorithmIdentifier algorithm = digestAlgorithmIdentifierFinder.find(digestType.getAlgorithm());
    return algorithm;
  }

  public static AlgorithmIdentifier getAlgorithmIdentifier(final SignatureType signatureType) {
    DefaultSignatureAlgorithmIdentifierFinder signatureAlgorithmIdentifierFinder = new DefaultSignatureAlgorithmIdentifierFinder();
    AlgorithmIdentifier algorithm = signatureAlgorithmIdentifierFinder.find(signatureType.getAlgorithm());
    return algorithm;
  }

  public static DigestType getDigestType(final AlgorithmIdentifier algorithmIdentifier) {
    if (algorithmIdentifier == null) {
      return null;
    }
    return Asn1Objects.getDigestType(algorithmIdentifier.getAlgorithm());
  }

  public static DigestType getDigestType(final ASN1ObjectIdentifier asn1ObjectIdentifier) {
    if (asn1ObjectIdentifier == null) {
      return null;
    }
    return DigestType.get(asn1ObjectIdentifier);
  }

  public static DigestType getDigestType(final String algorithm) {
    if (Strings.isNullOrEmpty(algorithm)) {
      return null;
    }
    for (DigestType dt : DigestType.values()) {
      if (dt.getAlgorithm().equalsIgnoreCase(algorithm)) {
        return dt;
      }
    }
    return null;
  }

  public static SignatureType getSignatureType(final AlgorithmIdentifier algorithmIdentifier) {
    if (algorithmIdentifier == null) {
      return null;
    }
    return Asn1Objects.getSignatureType(algorithmIdentifier.getAlgorithm());
  }

  public static SignatureType getSignatureType(final ASN1ObjectIdentifier asn1ObjectIdentifier) {
    if (asn1ObjectIdentifier == null) {
      return null;
    }
    return SignatureType.get(asn1ObjectIdentifier);
  }

  public static SignatureType getSignatureType(final String digestAlgorithm, final String encryptionAlgorithm) {
    AlgorithmIdentifier digestAlgorithmIdentifier = new AlgorithmIdentifier(new ASN1ObjectIdentifier(digestAlgorithm));
    AlgorithmIdentifier encryptionAlgorithmIdentifier = new AlgorithmIdentifier(new ASN1ObjectIdentifier(encryptionAlgorithm));
    DefaultCMSSignatureAlgorithmNameGenerator cmsSignatureAlgorithmNameGenerator = new DefaultCMSSignatureAlgorithmNameGenerator();
    String algorithm = cmsSignatureAlgorithmNameGenerator.getSignatureName(digestAlgorithmIdentifier, encryptionAlgorithmIdentifier);
    SignatureAlgorithmIdentifierFinder signatureAlgorithmIdentifierFinder = new DefaultSignatureAlgorithmIdentifierFinder();
    AlgorithmIdentifier algorithmIdentifier = signatureAlgorithmIdentifierFinder.find(algorithm);
    SignatureType signatureType = SignatureType.get(algorithmIdentifier);
    return signatureType;
  }

}
