package com.github.lsjunior.icrypto.core.store;

import java.io.OutputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.List;

import com.github.lsjunior.icrypto.core.Identity;

public interface Store {

  // list
  Collection<String> getAliases();

  boolean isCertificate(String alias);

  boolean isIdentity(String alias);

  // Get
  Identity getIdentity(String alias, String password);

  List<Certificate> getCertificate(String alias);

  // Add
  boolean add(String alias, String password, Identity identity);

  boolean add(String alias, List<Certificate> chain);

  boolean remove(String alias);

  // JCA
  KeyStore toKeyStore();

  // IO
  void write(OutputStream outputStream, String password);

}
