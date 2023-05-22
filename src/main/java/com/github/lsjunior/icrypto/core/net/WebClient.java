package com.github.lsjunior.icrypto.core.net;

import java.io.IOException;
import java.util.Map;

public interface WebClient {

  byte[] get(String url) throws IOException;

  byte[] post(String url, Map<String, String> properties) throws IOException;

  byte[] post(String url, byte[] req, Map<String, String> properties) throws IOException;

  byte[] execute(String url, byte[] req, Map<String, String> properties) throws IOException;

}
