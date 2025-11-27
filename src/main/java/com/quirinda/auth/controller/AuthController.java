package com.quirinda.auth.controller;

import com.quirinda.auth.dto.AuthRequest;
import com.quirinda.auth.dto.AuthResponse;
import com.quirinda.auth.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

	@Autowired
	private JwtUtil jwtUtil;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@PostMapping("/login")
	public AuthResponse login(@RequestBody AuthRequest request) {
		// Mock user validation - replace with database query in production
		if ("admin".equals(request.username()) && "admin123".equals(request.password())) {
			String token = jwtUtil.generateToken(request.username());
			return new AuthResponse(token, request.username(), "Login successful");
		}
		return new AuthResponse(null, null, "Invalid credentials");
	}

	@PostMapping("/register")
	public AuthResponse register(@RequestBody AuthRequest request) {
		// Mock registration - replace with database save in production
		String token = jwtUtil.generateToken(request.username());
		return new AuthResponse(token, request.username(), "User registered successfully");
	}

	@GetMapping("/validate")
	public AuthResponse validateToken(@RequestHeader("Authorization") String authHeader) {
		if (authHeader == null || !authHeader.startsWith("Bearer ")) {
			return new AuthResponse(null, null, "Invalid token format");
		}
		String token = authHeader.substring(7);
		if (jwtUtil.isTokenValid(token)) {
			String username = jwtUtil.extractUsername(token);
			return new AuthResponse(token, username, "Token is valid");
		}
		return new AuthResponse(null, null, "Invalid token");
	}

	@GetMapping("/health")
	public AuthResponse health() {
		return new AuthResponse(null, null, "Auth service is running");
	}
}
