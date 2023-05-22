package com.github.lsjunior.icrypto.core.crypt.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.OperatorException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;
import org.bouncycastle.util.io.pem.PemObject;

import com.github.lsjunior.icrypto.api.type.KeyPairType;
import com.github.lsjunior.icrypto.api.type.KeySizeType;
import com.github.lsjunior.icrypto.api.type.KeyType;
import com.github.lsjunior.icrypto.core.util.BcProvider;

public abstract class Keys {

  private Keys() {
    //
  }

  public static KeyPair newKeyPair(final KeyPairType type, final KeySizeType size) throws GeneralSecurityException {
    KeyPairGenerator generator = KeyPairGenerator.getInstance(type.getAlgorithm());
    generator.initialize(size.getSize());
    KeyPair keyPair = generator.generateKeyPair();
    return keyPair;
  }

  public static String toPkcs8PemEncoded(final PrivateKey privateKey, final String password) throws OperatorException, IOException {
    JceOpenSSLPKCS8EncryptorBuilder encryptorBuilder = new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.PBE_SHA1_3DES);
    encryptorBuilder.setPassword(password.toCharArray());
    OutputEncryptor outputEncryptor = encryptorBuilder.build();
    JcaPKCS8Generator jcaPKCS8Generator = new JcaPKCS8Generator(privateKey, outputEncryptor);
    PemObject pemObject = jcaPKCS8Generator.generate();

    StringWriter stringWriter = new StringWriter();

    JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter);
    pemWriter.writeObject(pemObject);
    pemWriter.close();

    return stringWriter.toString();
  }

  public static PrivateKey toPrivateKey(final String pkcs8PemEncoded, final String password) throws IOException, PKCSException {
    StringReader stringReader = new StringReader(pkcs8PemEncoded);
    PEMParser pemParser = new PEMParser(stringReader);
    PKCS8EncryptedPrivateKeyInfo pkcs8EncryptedPrivateKeyInfo = (PKCS8EncryptedPrivateKeyInfo) pemParser.readObject();
    JcePKCSPBEInputDecryptorProviderBuilder jcePKCSPBEInputDecryptorProviderBuilder = new JcePKCSPBEInputDecryptorProviderBuilder();
    PrivateKeyInfo privateKeyInfo = pkcs8EncryptedPrivateKeyInfo.decryptPrivateKeyInfo(jcePKCSPBEInputDecryptorProviderBuilder.build(password.toCharArray()));
    JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter().setProvider(BcProvider.PROVIDER_NAME);
    PrivateKey privateKey = jcaPEMKeyConverter.getPrivateKey(privateKeyInfo);
    return privateKey;
  }

  public static PrivateKey toPrivateKey(final InputStream inputStream, final KeyPairType type) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
    byte[] bytes = new byte[inputStream.available()];
    inputStream.read(bytes);

    return Keys.toPrivateKey(bytes, type);
  }

  public static PrivateKey toPrivateKey(final byte[] bytes, final KeyPairType type) throws NoSuchAlgorithmException, InvalidKeySpecException {
    PKCS8EncodedKeySpec specPrivate = new PKCS8EncodedKeySpec(bytes);
    KeyFactory factory = KeyFactory.getInstance(type.getAlgorithm());
    PrivateKey privateKey = factory.generatePrivate(specPrivate);
    return privateKey;
  }

  public static String toPemEncoded(final PublicKey publicKey) throws IOException {
    StringWriter sw = new StringWriter();
    JcaPEMWriter pemWriter = new JcaPEMWriter(sw);
    pemWriter.writeObject(publicKey);
    pemWriter.close();
    return sw.toString();
  }

  public static PublicKey toPublicKey(final Reader reader) throws IOException {
    PEMParser pemParser = new PEMParser(reader);
    JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
    SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(pemParser.readObject());
    PublicKey publicKey = converter.getPublicKey(publicKeyInfo);
    return publicKey;
  }

  public static PublicKey toPublicKey(final InputStream inputStream) throws IOException {
    InputStreamReader inputStreamReader = new InputStreamReader(inputStream);
    return Keys.toPublicKey(inputStreamReader);
  }

  public static PublicKey toPublicKey(final byte[] bytes) throws IOException {
    return Keys.toPublicKey(new ByteArrayInputStream(bytes));
  }

  public static PublicKey toPublicKey(final String pem) throws IOException {
    return Keys.toPublicKey(new StringReader(pem));
  }

  public static SecretKey toSecretKey(final byte[] bytes, final KeyType type) {
    SecretKeySpec secretKeySpec = new SecretKeySpec(bytes, type.getAlgorithm());
    return secretKeySpec;
  }

}
