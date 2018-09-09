package com.revature.controller;

import java.util.Map;

import org.springframework.cloud.netflix.feign.FeignClient;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;


@FeignClient("application-service")
public interface ApplicationClient {

	@PostMapping("/test-feign")
	@PreAuthorize("hasRole('ROLE_ADMIN')")
	public Map<String, String> testFeignClient();
	
	@PostMapping("/test-feign-user")
	@PreAuthorize("hasRole('ROLE_USER')")
	public Map<String, String> testFeignClientUser();
}
