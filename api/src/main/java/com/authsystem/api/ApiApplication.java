package com.authsystem.api;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class ApiApplication {

	public static void main(String[] args) {
		SpringApplication.run(ApiApplication.class, args);

		// Log startup information
        System.out.println("========================================");
        System.out.println(" Auth System API Started Successfully");
        System.out.println(" Access: http://localhost:8080/api/v1");
        System.out.println(" H2 Console: http://localhost:8080/api/v1/h2-console");
        System.out.println(" Health Check: http://localhost:8080/api/v1/actuator/health");
        System.out.println("========================================");
	}

}
