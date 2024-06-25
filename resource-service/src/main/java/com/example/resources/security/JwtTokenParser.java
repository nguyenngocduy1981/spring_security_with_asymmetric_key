package com.example.resources.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class JwtTokenParser {
    public Claims validateAndGetToken(String token) {
        try {
            String secret = new String(Files.readAllBytes(Paths.get(ClassLoader.getSystemResource("public_key.pem").toURI())));
            secret = secret.replaceAll("\\n", "")
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "");
            ;

            KeyFactory kf = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(secret));
            RSAPublicKey pubKey = (RSAPublicKey) kf.generatePublic(keySpecX509);

            return Jwts.parser()
                    .verifyWith(pubKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        }catch(Exception ex){
            ex.printStackTrace();
            return  null;
        }
    }
    public Set<SimpleGrantedAuthority> getRolesFromJWT(Claims claims){
        List<String> roles = (List<String>) claims.get("roles");
        return roles.stream()
                .map(it -> new SimpleGrantedAuthority("ROLE_"+it))
                .collect(Collectors.toSet());
    }
}
