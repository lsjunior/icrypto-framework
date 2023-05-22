package com.github.lsjunior.icrypto.core.net;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.util.Map;
import java.util.Map.Entry;

import com.google.common.base.Strings;
import com.google.common.io.ByteStreams;
import com.google.common.io.Closeables;

public class JdkWebClient implements WebClient {

  private static final int CONNECTION_TIMEOUT = 15000;

  private static final int READ_TIMEOUT = 60000;

  private int connectionTimeout;

  private int readTimeout;

  public JdkWebClient() {
    this(JdkWebClient.CONNECTION_TIMEOUT, JdkWebClient.READ_TIMEOUT);
  }

  public JdkWebClient(final int connectionTimeout, final int readTimeout) {
    super();
    this.connectionTimeout = connectionTimeout;
    this.readTimeout = readTimeout;
  }

  @Override
  public byte[] get(final String url) throws IOException {
    return this.get(new URL(url));
  }

  public byte[] get(final URL url) throws IOException {
    URLConnection connection = this.getUrlConnection("GET", url, null, false);
    byte[] bytes = this.getResponse(connection);
    return bytes;
  }

  @Override
  public byte[] post(final String url, final Map<String, String> properties) throws IOException {
    return this.post(url, null, properties);
  }

  @Override
  public byte[] post(String url, byte[] req, Map<String, String> properties) throws IOException {
    URLConnection connection = this.getUrlConnection("POST", new URL(url), properties, true);
    this.writeData(connection, req);
    byte[] bytes = this.getResponse(connection);
    return bytes;
  }

  @Override
  public byte[] execute(final String url, final byte[] req, final Map<String, String> properties) throws IOException {
    return this.execute(new URL(url), req, properties);
  }

  public byte[] execute(final URL url, final byte[] req, final Map<String, String> properties) throws IOException {
    URLConnection connection = this.getUrlConnection(null, url, properties, true);
    this.writeData(connection, req);
    byte[] bytes = this.getResponse(connection);
    return bytes;
  }

  private URLConnection getUrlConnection(final String method, final URL url, final Map<String, String> properties, final boolean output) throws IOException {
    URLConnection connection = url.openConnection();
    connection.setConnectTimeout(this.connectionTimeout);
    connection.setReadTimeout(this.readTimeout);
    connection.setUseCaches(false);

    if (properties != null) {
      for (Entry<String, String> property : properties.entrySet()) {
        connection.setRequestProperty(property.getKey(), property.getValue());
      }
    }

    if (output) {
      connection.setDoInput(true);
      connection.setDoOutput(true);
    }

    if (connection instanceof HttpURLConnection) {
      HttpURLConnection httpUrlConnection = (HttpURLConnection) connection;
      httpUrlConnection.setInstanceFollowRedirects(true);
      if (!Strings.isNullOrEmpty(method)) {
        httpUrlConnection.setRequestMethod(method);
      }
    }

    return connection;
  }

  private void writeData(final URLConnection connection, final byte[] data) throws IOException {
    try (OutputStream outputStream = connection.getOutputStream()) {
      outputStream.write(data);
    }
  }

  private byte[] getResponse(final URLConnection connection) throws IOException {
    if (connection instanceof HttpURLConnection) {
      HttpURLConnection httpUrlConnection = (HttpURLConnection) connection;
      int status = httpUrlConnection.getResponseCode();
      if (status == HttpURLConnection.HTTP_OK) {
        InputStream inputStream = connection.getInputStream();
        byte[] bytes = ByteStreams.toByteArray(inputStream);
        Closeables.closeQuietly(inputStream);
        return bytes;
      } else if ((status == HttpURLConnection.HTTP_MOVED_PERM) || (status == HttpURLConnection.HTTP_MOVED_TEMP) || (status == HttpURLConnection.HTTP_SEE_OTHER)) {
        String newUrl = httpUrlConnection.getHeaderField("Location");
        if ((!Strings.isNullOrEmpty(newUrl)) && ("GET".equals(httpUrlConnection.getRequestMethod()))) {
          return this.get(newUrl);
        }
      }
      return null;
    }

    InputStream inputStream = connection.getInputStream();
    byte[] bytes = ByteStreams.toByteArray(inputStream);
    Closeables.closeQuietly(inputStream);
    return bytes;
  }

}
