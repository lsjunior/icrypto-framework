package com.github.lsjunior.icrypto.core.signature.pades;

import java.io.Serializable;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.google.common.io.ByteSource;

public class VisibleSignatureParameters implements Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private ByteSource image;

  private int page;

  private int left;

  private int top;

  private int width;

  private int height;

  private int zoom;

  private String template;

  public VisibleSignatureParameters() {
    super();
    this.page = 1;
    this.left = 0;
    this.top = 0;
    this.width = 200;
    this.height = 100;
    this.zoom = 100;
  }

  public ByteSource getImage() {
    return this.image;
  }

  public void setImage(final ByteSource image) {
    this.image = image;
  }

  public int getPage() {
    return this.page;
  }

  public void setPage(final int page) {
    this.page = page;
  }

  public int getLeft() {
    return this.left;
  }

  public void setLeft(final int left) {
    this.left = left;
  }

  public int getTop() {
    return this.top;
  }

  public void setTop(final int top) {
    this.top = top;
  }

  public int getWidth() {
    return this.width;
  }

  public void setWidth(final int width) {
    this.width = width;
  }

  public int getHeight() {
    return this.height;
  }

  public void setHeight(final int height) {
    this.height = height;
  }

  public int getZoom() {
    return this.zoom;
  }

  public void setZoom(final int zoom) {
    this.zoom = zoom;
  }

  public String getTemplate() {
    return this.template;
  }

  public void setTemplate(final String template) {
    this.template = template;
  }

}
