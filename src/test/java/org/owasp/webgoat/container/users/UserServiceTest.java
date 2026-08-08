/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.users;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.function.Function;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

  @Mock private UserRepository userRepository;
  @Mock private UserProgressRepository userTrackerRepository;
  @Mock private JdbcTemplate jdbcTemplate;
  @Mock private Function<String, Flyway> flywayLessons;
  @Mock private PasswordEncoder passwordEncoder;

  @Test
  void shouldThrowExceptionWhenUserIsNotFound() {
    when(userRepository.findByUsername(any())).thenReturn(null);
    UserService userService =
        new UserService(
            userRepository,
            userTrackerRepository,
            jdbcTemplate,
            flywayLessons,
            List.of(),
            passwordEncoder);
    org.assertj.core.api.Assertions.assertThatThrownBy(
            () -> userService.loadUserByUsername("unknown"))
        .isInstanceOf(UsernameNotFoundException.class);
  }

  @Test
  void addUserStoresOnlyEncodedPassword() {
    var service =
        new UserService(
            userRepository,
            userTrackerRepository,
            jdbcTemplate,
            flywayLessons,
            List.of(),
            passwordEncoder);
    when(userRepository.existsByUsername("alice")).thenReturn(true);
    when(passwordEncoder.encode("plain-text-password")).thenReturn("$2a$10$encoded");

    service.addUser("alice", "plain-text-password");

    var savedUser = ArgumentCaptor.forClass(WebGoatUser.class);
    verify(userRepository).save(savedUser.capture());
    assertThat(savedUser.getValue().getPassword()).isEqualTo("$2a$10$encoded");
    assertThat(savedUser.getValue().getPassword()).isNotEqualTo("plain-text-password");
  }
}
