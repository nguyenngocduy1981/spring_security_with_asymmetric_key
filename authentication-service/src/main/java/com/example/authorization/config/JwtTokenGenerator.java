package com.example.authorization.config;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

public class JwtTokenGenerator {
    public static String generate(String username, String roles){
        List<String> roleList = Arrays.stream(roles.split(","))
                .map(it -> it.trim())
                .map(it -> it.toUpperCase())
                .collect(Collectors.toList());
        Instant now = Instant.now();

        try {
            String secret = new String(Files.readAllBytes(Paths.get(ClassLoader.getSystemResource("private_key.pem").toURI())));
            secret = secret.replaceAll("\\n", "")
                    .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                    .replace("-----END RSA PRIVATE KEY-----", "");

            // Base64 decode the result
            java.security.Security.addProvider(
                    new org.bouncycastle.jce.provider.BouncyCastleProvider()
            );
            byte [] pkcs8EncodedBytes = Base64.getDecoder().decode(secret);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(pkcs8EncodedBytes);
            PrivateKey privateKey = kf.generatePrivate(keySpecPKCS8);
            return Jwts.builder()
                    .signWith(privateKey)
                    .issuedAt(new Date(now.toEpochMilli()))
                    .expiration(new Date(now.plusSeconds(8000).toEpochMilli()))
                    .issuer("Duy")
                    .claim("username", username)
                    .claim("ten", "My Org")
                    .claim("scope", "ADMIN")
                    .claim("roles", roleList)
                    .compact();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
