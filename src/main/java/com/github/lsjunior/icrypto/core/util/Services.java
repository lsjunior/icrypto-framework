package com.github.lsjunior.icrypto.core.util;

import java.security.Provider;
import java.security.Provider.Service;
import java.security.Security;

import com.github.lsjunior.icrypto.api.type.ProviderType;
import com.github.lsjunior.icrypto.api.type.ServiceType;
import com.google.common.base.Strings;

public abstract class Services {

  private Services() {
    //
  }

  public static boolean hasProvider(final ProviderType provider) {
    return Services.getProvider(provider) != null;
  }

  public static boolean hasProvider(final String provider) {
    return Services.getProvider(provider) != null;
  }

  public static Provider getProvider(final ProviderType provider) {
    if (provider == null) {
      return null;
    }
    return Services.getProvider(provider.getType());
  }

  public static Provider getProvider(final String provider) {
    if (!Strings.isNullOrEmpty(provider)) {
      for (Provider prv : Security.getProviders()) {
        if (prv.getName().equals(provider)) {
          return prv;
        }
      }
    }
    return null;
  }

  public static boolean hasService(final ServiceType service) {
    return Services.getService(service) != null;
  }

  public static boolean hasService(final String service) {
    return Services.getService(service) != null;
  }

  public static boolean hasService(final ProviderType provider, final ServiceType service) {
    return Services.getService(provider, service) != null;
  }

  public static boolean hasService(final String provider, final String service) {
    return Services.getService(provider, service) != null;
  }

  public static Service getService(final ServiceType service) {
    if (service == null) {
      return null;
    }
    return Services.getService(service.getType());
  }

  public static Service getService(final String service) {
    if (!Strings.isNullOrEmpty(service)) {
      for (Provider prv : Security.getProviders()) {
        for (Service srv : prv.getServices()) {
          if (srv.getType().equals(service)) {
            return srv;
          }
        }
      }
    }
    return null;
  }

  public static Service getService(final ProviderType provider, final ServiceType service) {
    if ((provider == null) || (service == null)) {
      return null;
    }
    return Services.getService(provider.getType(), service.getType());
  }

  public static Service getService(final String provider, final String service) {
    Provider prv = Services.getProvider(provider);
    if (prv != null) {
      for (Service srv : prv.getServices()) {
        if (srv.getType().equals(service)) {
          return srv;
        }
      }
    }
    return null;
  }

}
