/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.pathtraversal;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.mock.web.MockMultipartFile;

class ProfileZipSlipTest {

  @TempDir Path webGoatDirectory;

  @Test
  void rejectsEntryThatEscapesExtractionDirectory() throws Exception {
    String markerName = "webgoat-zip-slip-" + UUID.randomUUID() + ".txt";
    Path escapedFile = Path.of(System.getProperty("java.io.tmpdir"), markerName);
    Files.deleteIfExists(escapedFile);
    var upload = zipUpload("../" + markerName, "escaped");

    var result =
        new ProfileZipSlip(webGoatDirectory.toString()).uploadFileHandler(upload, "alice");

    assertThat(result.getFeedback()).isEqualTo("path-traversal-profile-attempt");
    assertThat(escapedFile).doesNotExist();
  }

  @Test
  void acceptsEntryContainedInExtractionDirectory() throws Exception {
    var upload = zipUpload("images/profile.txt", "safe");

    var result =
        new ProfileZipSlip(webGoatDirectory.toString()).uploadFileHandler(upload, "alice");

    assertThat(result.getOutput()).isEqualTo("path-traversal-zip-slip.extracted");
  }

  private MockMultipartFile zipUpload(String entryName, String contents) throws Exception {
    var bytes = new ByteArrayOutputStream();
    try (var zip = new ZipOutputStream(bytes)) {
      zip.putNextEntry(new ZipEntry(entryName));
      zip.write(contents.getBytes());
      zip.closeEntry();
    }
    return new MockMultipartFile(
        "uploadedFileZipSlip", "profile.zip", "application/zip", bytes.toByteArray());
  }
}
