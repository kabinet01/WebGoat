/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static java.sql.ResultSet.CONCUR_READ_ONLY;
import static java.sql.ResultSet.TYPE_SCROLL_INSENSITIVE;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints(value = {"SqlStringInjectionHint3-1", "SqlStringInjectionHint3-2"})
public class SqlInjectionLesson3 implements AssignmentEndpoint {

  private static final Pattern EXPECTED_UPDATE =
      Pattern.compile(
          "^\\s*update\\s+employees\\s+set\\s+department\\s*=\\s*'([^']+)'\\s+where\\s+(last_name|userid)\\s*=\\s*'?([a-z0-9 -]+)'?\\s*;?\\s*$",
          Pattern.CASE_INSENSITIVE);

  private final LessonDataSource dataSource;

  public SqlInjectionLesson3(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjection/attack3")
  @ResponseBody
  public AttackResult completed(@RequestParam String query) {
    return injectableQuery(query);
  }

  protected AttackResult injectableQuery(String query) {
    Matcher requestedUpdate = query == null ? null : EXPECTED_UPDATE.matcher(query);
    if (requestedUpdate == null || !requestedUpdate.matches()) {
      return failed(this).build();
    }
    try (Connection connection = dataSource.getConnection()) {
      String predicateColumn = requestedUpdate.group(2).toLowerCase();
      String updateSql =
          "last_name".equals(predicateColumn)
              ? "UPDATE employees SET department = ? WHERE last_name = ?"
              : "UPDATE employees SET department = ? WHERE userid = ?";
      try (var statement = connection.prepareStatement(updateSql);
          var checkStatement =
              connection.prepareStatement(
                  "SELECT * FROM employees WHERE last_name = ?",
                  TYPE_SCROLL_INSENSITIVE,
                  CONCUR_READ_ONLY)) {
        statement.setString(1, requestedUpdate.group(1));
        statement.setString(2, requestedUpdate.group(3));
        statement.executeUpdate();
        checkStatement.setString(1, "Barnett");
        ResultSet results = checkStatement.executeQuery();
        StringBuilder output = new StringBuilder();
        // user completes lesson if the department of Tobi Barnett now is 'Sales'
        results.first();
        if (results.getString("department").equals("Sales")) {
          output.append("<span class='feedback-positive'>" + query + "</span>");
          output.append(SqlInjectionLesson8.generateTable(results));
          return success(this).output(output.toString()).build();
        } else {
          return failed(this).output(output.toString()).build();
        }

      } catch (SQLException sqle) {
        return failed(this).output(sqle.getMessage()).build();
      }
    } catch (Exception e) {
      return failed(this).output(this.getClass().getName() + " : " + e.getMessage()).build();
    }
  }
}
