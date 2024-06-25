package com.example.authorization.api;

import com.example.authorization.config.JwtTokenGenerator;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/login")
public class AuthenticationController {
    @PostMapping
    public Map<String, String> login(@RequestBody Map<String, String> data) {
        String userName = data.get("username");
        String roles = data.get("roles");

        // authenticate userName against Database
        // Here, just mock and generate JWT Token
        return Map.of("access_token", JwtTokenGenerator.generate(userName, roles));
    }
}
