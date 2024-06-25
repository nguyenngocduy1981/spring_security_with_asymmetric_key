package com.example.resources.api;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/hi")
public class HelloController {
    @GetMapping("/hello")
    public String say(Authentication auth) {
        System.out.println("auth:: " + auth);
        return UUID.randomUUID().toString() + " : " + LocalDateTime.now();
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('USER')")
    public Map<String, Object> sayUser(Authentication authentication) {
        return Map.of(
                "action", "User does action",
                "roles", "USER",
                "authentication", authentication
        );
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public Map<String, Object> sayAdmin(Authentication authentication) {
        return Map.of(
                "action", "Admnin does action",
                "roles", "ADMIN",
                "authentication", authentication
        );
    }

    @PostMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public Map<String, Object> addAdmin(@RequestBody Map<String, String> body,
                                        Authentication authentication) {
        return Map.of(
                "action", "Admnin posts data",
                "roles", "ADMIN",
                "data", body,
                "authentication", authentication
        );
    }

    @GetMapping("/user-admin")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public Map<String, Object> sayBoth(Authentication authentication) {
        return Map.of(
                "action", "User or Admnin does action",
                "roles", "USER, ADMIN",
                "authentication", authentication
        );
    }
}
