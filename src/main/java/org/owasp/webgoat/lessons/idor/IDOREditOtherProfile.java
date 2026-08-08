/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "idor.hints.otherProfile1",
  "idor.hints.otherProfile2",
  "idor.hints.otherProfile3",
  "idor.hints.otherProfile4",
  "idor.hints.otherProfile5",
  "idor.hints.otherProfile6",
  "idor.hints.otherProfile7",
  "idor.hints.otherProfile8",
  "idor.hints.otherProfile9"
})
public class IDOREditOtherProfile implements AssignmentEndpoint {

  private final LessonSession userSessionData;

  public IDOREditOtherProfile(LessonSession lessonSession) {
    this.userSessionData = lessonSession;
  }

  @PutMapping(path = "/IDOR/profile/{userId}", consumes = "application/json")
  @ResponseBody
  public AttackResult completed(
      @PathVariable("userId") String userId, @RequestBody UserProfile userSubmittedProfile) {

    String authUserId = (String) userSessionData.getValue("idor-authenticated-user-id");
    // Horizontal access control: the record being written is the one named in the path
    // ({userId}), and the caller's real identity is the one established server-side at login
    // (authUserId) -- never a self-reported id in the request body. A caller may only write
    // their own record unless they are an admin (nobody in this lesson's data set is).
    boolean isOwnRecord = authUserId != null && authUserId.equals(userId);
    UserProfile currentUserProfile = new UserProfile(userId);

    if (!isOwnRecord) {
      UserProfile callerProfile = authUserId != null ? new UserProfile(authUserId) : null;
      if (callerProfile == null || !callerProfile.isAdmin()) {
        return failed(this).feedback("idor.edit.profile.failure3").build();
      }
      // an authorized admin editing someone else's profile ...
      currentUserProfile.setColor(userSubmittedProfile.getColor());
      currentUserProfile.setRole(userSubmittedProfile.getRole());
      // we will persist in the session object for now in case we want to refer back or use it later
      userSessionData.setValue("idor-updated-other-profile", currentUserProfile);
      if (currentUserProfile.getRole() <= 1
          && currentUserProfile.getColor().equalsIgnoreCase("red")) {
        return success(this)
            .feedback("idor.edit.profile.success1")
            .output(currentUserProfile.profileToMap().toString())
            .build();
      }

      if (currentUserProfile.getRole() > 1
          && currentUserProfile.getColor().equalsIgnoreCase("red")) {
        return failed(this)
            .feedback("idor.edit.profile.failure1")
            .output(currentUserProfile.profileToMap().toString())
            .build();
      }

      if (currentUserProfile.getRole() <= 1
          && !currentUserProfile.getColor().equalsIgnoreCase("red")) {
        return failed(this)
            .feedback("idor.edit.profile.failure2")
            .output(currentUserProfile.profileToMap().toString())
            .build();
      }

      // else
      return failed(this)
          .feedback("idor.edit.profile.failure3")
          .output(currentUserProfile.profileToMap().toString())
          .build();
    }

    // legitimate self-service: a user may always edit their own profile
    currentUserProfile.setColor(userSubmittedProfile.getColor());
    currentUserProfile.setRole(userSubmittedProfile.getRole());
    userSessionData.setValue("idor-updated-own-profile", currentUserProfile);
    return success(this)
        .feedback("idor.edit.profile.success2")
        .output(currentUserProfile.profileToMap().toString())
        .build();
  }
}
