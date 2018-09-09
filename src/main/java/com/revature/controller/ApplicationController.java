package com.revature.controller;

import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.revature.service.ApplicationService;

@RestController
public class ApplicationController {
	
	private static Logger log = LoggerFactory.getLogger(ApplicationController.class);

	@Autowired
	private ApplicationService applicationService;
	
	@RequestMapping("/")
	@PreAuthorize("hasRole('ROLE_ADMIN')")
	public String getMessageFromService() {
		log.info("Inside ApplicationController.getMessageFromService() method");
		return applicationService.getMessage() + " " + SecurityContextHolder.getContext().getAuthentication().toString();
	}
	
	@PostMapping("/")
	public String getMessageFromServiceSecure() {
		log.info("Inside ApplicationController.getMessageFromServiceSecure() method");
		return applicationService.getMessage() + " " + SecurityContextHolder.getContext().getAuthentication().toString();
	}
	
	@PostMapping("/test-feign")
	public Map<String, String> testFeignClient() {
		log.info("Inside ApplicationController.testFeignClient()");
		Map<String, String> message = new HashMap<>();
		message.put("message", applicationService.getMessage() + " using FeignClients, (Admin) " + SecurityContextHolder.getContext().getAuthentication().getName() + "!");
		return message;
	}
	
	@PostMapping("/test-feign-user")
	public Map<String, String> testFeignClientUser() {
		log.info("Inside ApplicationConteoller.testFeignClientsUser()");
		Map<String, String> message = new HashMap<>();
		message.put("message", applicationService.getMessage() + " using FeignClients, (User) " + SecurityContextHolder.getContext().getAuthentication().getName() + "!");
		return message;
	}
	
	@RequestMapping("/another-endpoint")
	public String getAnotherMessageFromService() {
		return applicationService.getAnotherMessage();
	}
	
	@RequestMapping("/some-message")
	public String getSomeMessageFromService() {
		return applicationService.getSomeMessage();
	}
	
	@RequestMapping("/some-deep-property")
	public String getSomeDeepPropertyFromService() {
		return applicationService.getSomeDeepProperty();
	}
}
