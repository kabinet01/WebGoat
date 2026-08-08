/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;
import static org.springframework.http.MediaType.ALL_VALUE;

import com.google.common.collect.Lists;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"csrf-review-hint1", "csrf-review-hint2", "csrf-review-hint3"})
public class ForgedReviews implements AssignmentEndpoint {

  private static DateTimeFormatter fmt = DateTimeFormatter.ofPattern("yyyy-MM-dd, HH:mm:ss");

  private static final Map<String, List<Review>> userReviews = new HashMap<>();
  private static final List<Review> REVIEWS = new ArrayList<>();
  private static final String CSRF_TOKEN_HEADER = "X-CSRF-Token";
  private static final String CSRF_TOKEN_SESSION_KEY = "csrf-review-token";

  private final LessonSession userSessionData;

  public ForgedReviews(LessonSession userSessionData) {
    this.userSessionData = userSessionData;
  }

  static {
    REVIEWS.add(
        new Review("secUriTy", LocalDateTime.now().format(fmt), "This is like swiss cheese", 0));
    REVIEWS.add(new Review("webgoat", LocalDateTime.now().format(fmt), "It works, sorta", 2));
    REVIEWS.add(new Review("guest", LocalDateTime.now().format(fmt), "Best, App, Ever", 5));
    REVIEWS.add(
        new Review(
            "guest",
            LocalDateTime.now().format(fmt),
            "This app is so insecure, I didn't even post this review, can you pull that off too?",
            1));
  }

  @GetMapping(
      path = "/csrf/review",
      produces = MediaType.APPLICATION_JSON_VALUE,
      consumes = ALL_VALUE)
  @ResponseBody
  public Collection<Review> retrieveReviews(
      @CurrentUsername String username, HttpServletResponse response) {
    // Issue a fresh, unpredictable, per-session anti-CSRF token every time the page is
    // (re)loaded. Only a same-origin caller can read this response (and therefore this
    // header), so a forged cross-site page has no way to learn the value it must echo back
    // on /csrf/review (POST).
    String token = UUID.randomUUID().toString();
    userSessionData.setValue(CSRF_TOKEN_SESSION_KEY, token);
    response.setHeader(CSRF_TOKEN_HEADER, token);

    Collection<Review> allReviews = Lists.newArrayList();
    Collection<Review> newReviews = userReviews.get(username);
    if (newReviews != null) {
      allReviews.addAll(newReviews);
    }

    allReviews.addAll(REVIEWS);

    return allReviews;
  }

  @PostMapping("/csrf/review")
  @ResponseBody
  public AttackResult createNewReview(
      String reviewText,
      Integer stars,
      String validateReq,
      HttpServletRequest request,
      @CurrentUsername String username) {
    final String host = (request.getHeader("host") == null) ? "NULL" : request.getHeader("host");
    final String referer =
        (request.getHeader("referer") == null) ? "NULL" : request.getHeader("referer");

    // Primary defense: the request must carry the unpredictable, per-session anti-CSRF
    // token that was handed out on the last GET of this page. A cross-site forger cannot
    // read that token (same-origin policy blocks reading the response) and so cannot
    // reproduce it, regardless of whether it can make the browser send the request.
    Object expectedToken = userSessionData.getValue(CSRF_TOKEN_SESSION_KEY);
    if (expectedToken == null || validateReq == null || !validateReq.equals(expectedToken)) {
      return failed(this).feedback("csrf-you-forgot-something").build();
    }

    // Secondary defense: reject requests whose Referer host does not match the host the
    // request was sent to (defense in depth on top of the token check).
    if (!"NULL".equals(referer)) {
      String[] refererArr = referer.split("/");
      if (refererArr.length > 2 && !refererArr[2].equals(host)) {
        return failed(this).feedback("csrf-you-forgot-something").build();
      }
    }

    Review review = new Review();
    review.setText(reviewText);
    review.setDateTime(LocalDateTime.now().format(fmt));
    review.setUser(username);
    review.setStars(stars);
    var reviews = userReviews.getOrDefault(username, new ArrayList<>());
    reviews.add(review);
    userReviews.put(username, reviews);

    return success(this).feedback("csrf-review.success").build();
  }
}
