package com.github.lsjunior.icrypto.core.timestamp.impl;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.ICryptoException;
import com.google.common.io.BaseEncoding;
import com.google.common.io.ByteStreams;
import com.google.common.io.Closeables;

public class HttpTimeStampProvider extends AbstractTimeStampProvider {

  public static final String CONTENT_TYPE_PROPERTY = "Content-Type";

  public static final String CONTENT_TYPE_VALUE = "application/timestamp-query";

  public static final String CONTENT_TRANSFER_ENCODING_PROPERTY = "Content-Transfer-Encoding";

  public static final String CONTENT_TRANSFER_ENCODING_BINARY = "binary";

  public static final String CONTENT_TRANSFER_ENCODING_BASE64 = "base64";

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private final URL url;

  private final String encoding;

  public HttpTimeStampProvider(final String url) throws MalformedURLException {
    this(new URL(url), HttpTimeStampProvider.CONTENT_TRANSFER_ENCODING_BINARY);
  }

  public HttpTimeStampProvider(final URL url) {
    this(url, HttpTimeStampProvider.CONTENT_TRANSFER_ENCODING_BINARY);
  }

  public HttpTimeStampProvider(final String url, final String encoding) throws MalformedURLException {
    this(new URL(url), encoding);
  }

  public HttpTimeStampProvider(final URL url, final String encoding) {
    super();
    this.url = url;
    this.encoding = encoding;
  }

  @Override
  protected byte[] execute(final byte[] request) {
    URLConnection connection = null;
    try {
      connection = this.url.openConnection();

      connection.setDoInput(true);
      connection.setDoOutput(true);
      connection.setUseCaches(false);

      this.setConnectionProperties(connection);

      OutputStream outputStream = connection.getOutputStream();

      this.writeBytes(outputStream, request);

      Closeables.close(outputStream, true);

      InputStream inputStream = connection.getInputStream();

      String encoding = connection.getContentEncoding();

      byte[] bytes = this.readBytes(inputStream, encoding);

      Closeables.close(inputStream, true);

      return bytes;
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }

  protected void setConnectionProperties(final URLConnection connection) {
    connection.setConnectTimeout(5000);
    connection.setReadTimeout(15000);
    connection.setRequestProperty(HttpTimeStampProvider.CONTENT_TYPE_PROPERTY, HttpTimeStampProvider.CONTENT_TYPE_VALUE);
    connection.setRequestProperty(HttpTimeStampProvider.CONTENT_TRANSFER_ENCODING_PROPERTY, this.encoding);
  }

  protected void writeBytes(final OutputStream outputStream, final byte[] bytes) throws IOException {
    outputStream.write(bytes);
  }

  protected byte[] readBytes(final InputStream inputStream, final String encoding) throws IOException {
    byte[] bytes = ByteStreams.toByteArray(inputStream);
    if (HttpTimeStampProvider.CONTENT_TRANSFER_ENCODING_BASE64.equals(encoding)) {
      bytes = BaseEncoding.base64().decode(new String(bytes));
    }
    return bytes;
  }

}
