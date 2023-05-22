package com.github.lsjunior.icrypto.core.timestamp.impl;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.ICryptoException;
import com.github.lsjunior.icrypto.ICryptoLog;
import com.google.common.io.ByteStreams;

public class SocketTimeStampProvider extends AbstractTimeStampProvider {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private final SocketAddress address;

  public SocketTimeStampProvider(final SocketAddress address) {
    super();
    this.address = address;
  }

  public SocketTimeStampProvider(final String address, final int port) {
    super();
    this.address = new InetSocketAddress(address, port);
  }

  @Override
  protected byte[] execute(final byte[] request) {
    Socket socket = null;
    try {
      socket = new Socket();
      socket.connect(this.address);

      OutputStream outputStream = socket.getOutputStream();

      this.writeRequest(outputStream, request);

      socket.shutdownOutput();

      InputStream inputStream = socket.getInputStream();

      byte[] bytes = this.readResponse(inputStream);

      socket.shutdownInput();
      return bytes;
    } catch (Exception e) {
      throw new ICryptoException(e);
    } finally {
      if ((socket != null) && (socket.isConnected())) {
        try {
          socket.close();
        } catch (IOException e) {
          ICryptoLog.getLogger().warn(e.getMessage(), e);
        }
      }
    }
  }

  protected void writeRequest(final OutputStream outputStream, final byte[] bytes) throws IOException {
    outputStream.write(bytes);
  }

  protected byte[] readResponse(final InputStream inputStream) throws IOException {
    return ByteStreams.toByteArray(inputStream);
  }

}
