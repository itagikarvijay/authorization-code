package com.oauth.authorization.dataloader;

import com.oauth.authorization.entity.Role;
import com.oauth.authorization.entity.User;
import com.oauth.authorization.repo.RoleRepository;
import com.oauth.authorization.repo.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class DataLoader implements CommandLineRunner {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    public DataLoader(UserRepository userRepository, RoleRepository roleRepository) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
    }

    @Override
    public void run(String... args) {
        // Seed roles if not present
        if (roleRepository.count() == 0) {
            Role userRole = new Role("USER");
            Role adminRole = new Role("ADMIN");
            roleRepository.saveAll(List.of(userRole, adminRole));

            // Seed users
            User john = new User("vijay", "{noop}vijay123", "john@example.com", "USER");
            userRepository.save(john);

            User admin = new User("admin", "{noop}admin123", "admin@example.com", "ADMIN");
            userRepository.save(admin);
        }
    }
}
