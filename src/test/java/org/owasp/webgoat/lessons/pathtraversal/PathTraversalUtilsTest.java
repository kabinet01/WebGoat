/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.pathtraversal;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PathTraversalUtilsTest {

  @TempDir Path temporaryDirectory;

  @Test
  void rejectsArchiveEntryOutsideExtractionDirectory() throws Exception {
    assertThat(PathTraversalUtils.resolveWithinDirectory(temporaryDirectory, "../outside.txt"))
        .isNull();
    assertThat(PathTraversalUtils.resolveWithinDirectory(temporaryDirectory, "/tmp/outside.txt"))
        .isNull();
  }

  @Test
  void acceptsNestedEntryInsideExtractionDirectory() throws Exception {
    assertThat(PathTraversalUtils.resolveWithinDirectory(temporaryDirectory, "images/avatar.png"))
        .isEqualTo(temporaryDirectory.resolve("images/avatar.png"));
  }
}
