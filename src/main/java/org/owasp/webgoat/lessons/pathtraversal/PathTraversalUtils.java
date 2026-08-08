/*
 * SPDX-FileCopyrightText: Copyright © 2020 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.pathtraversal;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;

/**
 * Resolves user-supplied file names against a fixed base directory and rejects anything that
 * escapes it, regardless of how the traversal is expressed (relative {@code ../}, nested
 * sequences such as {@code ....//}, an absolute path, or a value that only reveals the traversal
 * once it has been URL-decoded). Every entry point in the path-traversal lesson family that turns
 * user input into a file on disk should go through this instead of stripping or blacklisting
 * substrings.
 */
final class PathTraversalUtils {

  private PathTraversalUtils() {}

  /**
   * Resolves {@code requestedName} against {@code baseDirectory}.
   *
   * @return the resolved {@link File} when it canonically resides inside {@code baseDirectory},
   *     or {@code null} when the requested name would escape the directory.
   */
  static File resolveWithinDirectory(File baseDirectory, String requestedName) throws IOException {
    Path base = baseDirectory.getCanonicalFile().toPath().normalize();
    Path resolved = base.resolve(requestedName).normalize();
    if (!resolved.startsWith(base)) {
      return null;
    }
    return resolved.toFile();
  }
}
