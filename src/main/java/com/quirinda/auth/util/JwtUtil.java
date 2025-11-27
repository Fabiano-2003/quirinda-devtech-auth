package com.quirinda.auth.util;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import java.util.Date;
import javax.crypto.SecretKey;

@Component
public class JwtUtil {

	@Value("${jwt.secret:QuirindasDevTechSecretKeyForAuthenticationAndAuthorization123456}")
	private String secret;

	@Value("${jwt.expiration:86400000}")
	private long expiration;

	private SecretKey getSigningKey() {
		return Keys.hmacShaKeyFor(secret.getBytes());
	}

	public String generateToken(String username) {
		return Jwts.builder()
			.subject(username)
			.issuedAt(new Date())
			.expiration(new Date(System.currentTimeMillis() + expiration))
			.signWith(getSigningKey(), SignatureAlgorithm.HS256)
			.compact();
	}

	public String extractUsername(String token) {
		return Jwts.parserBuilder()
			.setSigningKey(getSigningKey())
			.build()
			.parseClaimsJws(token)
			.getBody()
			.getSubject();
	}

	public boolean isTokenValid(String token) {
		try {
			Jwts.parserBuilder()
				.setSigningKey(getSigningKey())
				.build()
				.parseClaimsJws(token);
			return true;
		} catch (Exception e) {
			return false;
		}
	}
}
