package com.github.lsjunior.icrypto.core.util;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.security.Provider;

import com.google.common.base.CharMatcher;

public abstract class Providers {

  public static final String PKCS11_PROVIDER_CLASS = "sun.security.pkcs11.SunPKCS11";

  private Providers() {
    //
  }

  public static Provider toPkcs11Provider(final String name, final String library) throws ClassNotFoundException, SecurityException, ReflectiveOperationException {
    return Providers.toProvider(Providers.PKCS11_PROVIDER_CLASS, name, library);
  }

  @SuppressWarnings("unchecked")
  public static Provider toProvider(final String className, final String name, final String library) throws ClassNotFoundException, SecurityException, ReflectiveOperationException {
    StringBuilder builder = new StringBuilder();
    builder.append("name=" + CharMatcher.anyOf(" ").removeFrom(name));
    builder.append("\n");
    builder.append("library=" + library);

    Class<Provider> clazz = (Class<Provider>) Class.forName(className);
    InputStream inputStream = new ByteArrayInputStream(builder.toString().getBytes());
    Constructor<Provider> constructor = clazz.getConstructor(InputStream.class);
    Provider provider = constructor.newInstance(inputStream);

    return provider;
  }

}
