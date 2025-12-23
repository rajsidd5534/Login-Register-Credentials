package com.exampleSecurityCode.securityCode.controller;

import com.exampleSecurityCode.securityCode.DTO.ChangePasswordRequest;
import com.exampleSecurityCode.securityCode.repository.UserRepository;
import com.exampleSecurityCode.securityCode.security.JwtUtil;
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

    private final UserRepository repository;
    private final JwtUtil jwtUtil;
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    @PostMapping("/register")
    public String register(@RequestBody User user){
        if(repository.existsByEmail(user.getEmail()))
            return "Email already taken";

        user.setPassword(encoder.encode(user.getPassword()));
        repository.save(user);
        return "Account created successfully";
    }

    @PostMapping("/login")
    public String login(@RequestBody User reqUser){
        User user = repository.findByEmail(reqUser.getEmail())
                .orElseThrow(()-> new RuntimeException("user not found"));

        if (!encoder.matches(reqUser.getPassword(), user.getPassword()))
            return "Invalid password";

        return jwtUtil.generateToken(user.getEmail()); // return JWT token
    }

    @GetMapping("/me")
    public User profile() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String email = auth.getName();
        return repository.findByEmail(email).orElseThrow();
    }
    @PostMapping("/change-password")
    public String changePassword(@RequestBody ChangePasswordRequest request,
                                 Authentication authentication) {

        String email = authentication.getName(); // get logged-in user's email

        User user = repository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!encoder.matches(request.getOldPassword(), user.getPassword())) {
            return "Old password is incorrect";
        }

        user.setPassword(encoder.encode(request.getNewPassword()));
        repository.save(user);

        return "Password updated successfully";
    }
}
