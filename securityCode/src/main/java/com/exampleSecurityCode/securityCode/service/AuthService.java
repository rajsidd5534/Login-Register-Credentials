package com.exampleSecurityCode.securityCode.service;
import com.exampleSecurityCode.securityCode.DTO.ChangePasswordRequest;
import com.exampleSecurityCode.securityCode.repository.UserRepository;
import com.exampleSecurityCode.securityCode.security.JwtUtil;
import com.exampleSecurityCode.securityCode.user.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository repository;
    private final JwtUtil jwtUtil;
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    // REGISTER
    public String register(User user) {
        if (repository.existsByEmail(user.getEmail())) {
            return "Email already taken";
        }
        user.setPassword(encoder.encode(user.getPassword()));
        repository.save(user);
        return "Account created successfully";
    }

    // LOGIN
    public String login(String email, String password) {
        User user = repository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!encoder.matches(password, user.getPassword())) {
            return "Invalid password";
        }

        return jwtUtil.generateToken(email);
    }

    // PROFILE
    public User profile(Authentication authentication) {
        String email = authentication.getName();
        return repository.findByEmail(email).orElseThrow();
    }

    // CHANGE PASSWORD
    public String changePassword(ChangePasswordRequest request,
                                 Authentication authentication) {

        String email = authentication.getName();
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