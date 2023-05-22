package com.github.lsjunior.icrypto.core.store.impl;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreSpi;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.ICryptoException;
import com.github.lsjunior.icrypto.ICryptoLog;
import com.github.lsjunior.icrypto.api.type.KeyStoreType;
import com.github.lsjunior.icrypto.api.type.ProviderType;
import com.github.lsjunior.icrypto.core.Identity;
import com.github.lsjunior.icrypto.core.store.Store;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;

public class JcaStore implements Store, Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private KeyStore keyStore;

  public JcaStore(final KeyStore keyStore) {
    super();
    this.keyStore = keyStore;
  }

  public JcaStore(final KeyStoreType keyStoreType) {
    super();
    try {
      this.keyStore = KeyStore.getInstance(keyStoreType.getType());
      this.keyStore.load(null, null);
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }

  @Override
  public Collection<String> getAliases() {
    try {
      Enumeration<String> aliases = this.keyStore.aliases();
      List<String> list = Collections.list(aliases);
      return list;
    } catch (GeneralSecurityException e) {
      throw new ICryptoException(e);
    }
  }

  @Override
  public boolean isCertificate(final String alias) {
    try {
      if (this.keyStore.isCertificateEntry(alias)) {
        return true;
      }

      return false;
    } catch (GeneralSecurityException e) {
      throw new ICryptoException(e);
    }
  }

  @Override
  public boolean isIdentity(final String alias) {
    try {
      if (this.keyStore.isKeyEntry(alias)) {
        return true;
      }

      return false;
    } catch (GeneralSecurityException e) {
      throw new ICryptoException(e);
    }
  }

  @Override
  public List<Certificate> getCertificate(final String alias) {
    try {
      if ((this.keyStore.isCertificateEntry(alias)) || (this.keyStore.isKeyEntry(alias))) {
        Certificate[] chain = this.keyStore.getCertificateChain(alias);
        if (chain == null) {
          Certificate certificate = this.keyStore.getCertificate(alias);
          if (certificate != null) {
            chain = new Certificate[] {certificate};
          }
        }
        return Lists.newArrayList(chain);
      }

      return null;
    } catch (GeneralSecurityException e) {
      throw new ICryptoException(e);
    }
  }

  @Override
  public Identity getIdentity(final String alias, final String password) {
    try {
      if (this.keyStore.isKeyEntry(alias)) {
        Key key = this.keyStore.getKey(alias, password != null ? password.toCharArray() : null);
        if (key instanceof PrivateKey) {
          Certificate[] chain = this.keyStore.getCertificateChain(alias);
          return new Identity((PrivateKey) key, Lists.newArrayList(chain));
        }
      }

      return null;
    } catch (GeneralSecurityException e) {
      throw new ICryptoException(e);
    }
  }

  @Override
  public boolean add(final String alias, final List<Certificate> chain) {
    try {
      this.keyStore.setCertificateEntry(alias, chain.get(0));
      if (chain.size() > 1) {
        for (int i = 1; i < chain.size(); i++) {
          this.keyStore.setCertificateEntry(alias + i, chain.get(i));
        }
      }

      return true;
    } catch (GeneralSecurityException e) {
      throw new ICryptoException(e);
    }
  }

  @Override
  public boolean add(final String alias, final String password, final Identity identity) {
    try {
      this.keyStore.setKeyEntry(alias, identity.getPrivateKey(), password != null ? password.toCharArray() : null, Iterables.toArray(identity.getChain(), Certificate.class));
      return true;
    } catch (GeneralSecurityException e) {
      throw new ICryptoException(e);
    }
  }

  @Override
  public boolean remove(final String alias) {
    try {
      this.keyStore.deleteEntry(alias);
      return true;
    } catch (GeneralSecurityException e) {
      throw new ICryptoException(e);
    }
  }

  @Override
  public KeyStore toKeyStore() {
    return this.keyStore;
  }

  // IO
  @Override
  public void write(final OutputStream outputStream, final String password) {
    try {
      this.keyStore.store(outputStream, password != null ? password.toCharArray() : null);
    } catch (GeneralSecurityException | IOException e) {
      throw new ICryptoException(e);
    }
  }

  public static JcaStore read(final InputStream inputStream, final String password) {
    return JcaStore.read(inputStream, password, KeyStoreType.PKCS12, (Provider) null);
  }

  public static JcaStore read(final InputStream inputStream, final String password, final KeyStoreType keyStoreType) {
    return JcaStore.read(inputStream, password, keyStoreType, (Provider) null);
  }

  public static JcaStore read(final InputStream inputStream, final String password, final KeyStoreType keyStoreType, final String provider) {
    return JcaStore.read(inputStream, password, keyStoreType, Security.getProvider(provider));
  }

  public static JcaStore read(final InputStream inputStream, final String password, final KeyStoreType keyStoreType, final ProviderType provider) {
    return JcaStore.read(inputStream, password, keyStoreType, Security.getProvider(provider.getType()));
  }

  public static JcaStore read(final InputStream inputStream, final String password, final KeyStoreType keyStoreType, final Provider provider) {
    try {
      KeyStore keyStore = null;
      if (provider != null) {
        keyStore = KeyStore.getInstance(keyStoreType.getType(), provider);
      } else {
        keyStore = KeyStore.getInstance(keyStoreType.getType());
      }

      // KeyStore.PasswordProtection passwordProtection = new KeyStore.PasswordProtection(password
      // != null ? password.toCharArray() : null);
      // KeyStore.LoadStoreParameter loadStoreParameter = new KeyStore.LoadStoreParameter() {
      //
      // @Override
      // public ProtectionParameter getProtectionParameter() {
      // return passwordProtection;
      // }
      //
      // };
      // keyStore.load(loadStoreParameter);

      keyStore.load(inputStream, password != null ? password.toCharArray() : null);

      if (keyStoreType == KeyStoreType.WINDOWS_MY) {
        JcaStore.doFixWindowsMyAliases(keyStore);
      }

      return new JcaStore(keyStore);
    } catch (GeneralSecurityException | IOException e) {
      throw new ICryptoException(e);
    }
  }

  /**
   * <http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=6672015>
   * <http://bugs.java.com/bugdatabase/view_bug.do?bug_id=6483657>
   */
  private static void doFixWindowsMyAliases(final KeyStore keyStore) {
    try {
      Field field = keyStore.getClass().getDeclaredField("keyStoreSpi");
      field.setAccessible(true);

      KeyStoreSpi keyStoreVeritable = (KeyStoreSpi) field.get(keyStore);

      field = keyStoreVeritable.getClass().getEnclosingClass().getDeclaredField("entries");
      field.setAccessible(true);
      if (field.get(keyStoreVeritable) instanceof Map) {
        return;
      }

      if ("sun.security.mscapi.KeyStore$MY".equals(keyStoreVeritable.getClass().getName())) {
        field = keyStoreVeritable.getClass().getEnclosingClass().getDeclaredField("entries");
        field.setAccessible(true);

        Collection<?> entries = (Collection<?>) field.get(keyStoreVeritable);

        for (Object entry : entries) {
          field = entry.getClass().getDeclaredField("certChain");
          field.setAccessible(true);
          X509Certificate[] certificates = (X509Certificate[]) field.get(entry);
          String hashCode = Integer.toString(certificates[0].hashCode());

          field = entry.getClass().getDeclaredField("alias");
          field.setAccessible(true);
          String alias = (String) field.get(entry);

          if (!alias.equals(hashCode)) {
            field.set(entry, alias.concat(" - ").concat(hashCode));
          }
        }
      }
    } catch (Exception e) {
      ICryptoLog.getLogger().debug(e.getMessage(), e);
    }
  }

}
