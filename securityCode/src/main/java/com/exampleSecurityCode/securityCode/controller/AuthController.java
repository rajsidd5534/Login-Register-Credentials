package com.exampleSecurityCode.securityCode.controller;

import com.exampleSecurityCode.securityCode.DTO.ChangePasswordRequest;
import com.exampleSecurityCode.securityCode.repository.UserRepository;
import com.exampleSecurityCode.securityCode.security.JwtUtil;
import com.exampleSecurityCode.securityCode.service.AuthService;
import com.exampleSecurityCode.securityCode.user.User;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public String register(@RequestBody User user) {
        return authService.register(user);
    }

    @PostMapping("/login")
    public String login(@RequestBody User user) {
        return authService.login(user.getEmail(), user.getPassword());
    }

    @GetMapping("/me")
    public User profile(Authentication authentication) {
        return authService.profile(authentication);
    }

    @PostMapping("/change-password")
    public String changePassword(@RequestBody ChangePasswordRequest request,
                                 Authentication authentication) {
        return authService.changePassword(request, authentication);
    }
}