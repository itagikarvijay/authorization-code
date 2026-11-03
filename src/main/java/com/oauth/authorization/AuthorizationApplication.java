package com.oauth.authorization;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;

@SpringBootApplication
//@EnableDiscoveryClient
public class AuthorizationApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthorizationApplication.class, args);
	}

	@GetMapping("/login")
	public String login() {
		// This returns the name of your login view (e.g., login.html in templates folder)
		return "login";
	}

}
