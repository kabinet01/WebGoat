/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.clientsidefiltering;

import com.google.common.collect.Lists;
import java.util.List;
import java.util.Optional;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author nbaars
 * @since 4/6/17.
 */
@RestController
@RequestMapping("/clientSideFiltering/challenge-store")
public class ShopEndpoint {

  @AllArgsConstructor
  private class CheckoutCodes {

    @Getter private List<CheckoutCode> codes;

    public Optional<CheckoutCode> get(String code) {
      return codes.stream().filter(c -> c.getCode().equals(code)).findFirst();
    }
  }

  @AllArgsConstructor
  @Getter
  private class CheckoutCode {
    private String code;
    private int discount;
  }

  private CheckoutCodes checkoutCodes;

  public ShopEndpoint() {
    List<CheckoutCode> codes = Lists.newArrayList();
    codes.add(new CheckoutCode("webgoat", 25));
    codes.add(new CheckoutCode("owasp", 25));
    codes.add(new CheckoutCode("owasp-webgoat", 50));
    this.checkoutCodes = new CheckoutCodes(codes);
  }

  // The super/free coupon is an internal-only code and must never be handed back to the
  // client, either individually or as part of the full listing below: filtering which
  // coupons a client may learn about has to happen server-side, not by shipping every
  // coupon and trusting the client to only display the "public" ones.
  @GetMapping(value = "/coupons/{code}", produces = MediaType.APPLICATION_JSON_VALUE)
  public CheckoutCode getDiscountCode(@PathVariable String code) {
    return checkoutCodes.get(code).orElse(new CheckoutCode("no", 0));
  }

  @GetMapping(value = "/coupons", produces = MediaType.APPLICATION_JSON_VALUE)
  public CheckoutCodes all() {
    List<CheckoutCode> all = Lists.newArrayList();
    all.addAll(this.checkoutCodes.getCodes());
    return new CheckoutCodes(all);
  }
}
