/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.webwolf;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.test.util.ReflectionTestUtils;

class FileServerTest {

  @TempDir Path fileLocation;

  private FileServer fileServer;
  private TestingAuthenticationToken authentication;

  @BeforeEach
  void setup() {
    fileServer = new FileServer();
    ReflectionTestUtils.setField(fileServer, "fileLocation", fileLocation.toString());
    authentication = new TestingAuthenticationToken("alice", "password");
  }

  @Test
  void rejectsTraversalFilename() {
    var upload = new MockMultipartFile("file", "../escaped.txt", "text/plain", "nope".getBytes());

    assertThatThrownBy(() -> fileServer.importFile(upload, authentication))
        .isInstanceOf(java.io.IOException.class)
        .hasMessage("Invalid file name");
    assertThat(fileLocation.resolve("escaped.txt")).doesNotExist();
  }

  @Test
  void storesSimpleFilenameInAuthenticatedUsersDirectory() throws Exception {
    var upload = new MockMultipartFile("file", "safe.txt", "text/plain", "ok".getBytes());

    fileServer.importFile(upload, authentication);

    assertThat(Files.readString(fileLocation.resolve("alice/safe.txt"))).isEqualTo("ok");
  }
}
