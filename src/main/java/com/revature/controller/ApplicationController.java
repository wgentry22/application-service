package com.revature.controller;

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
@PreAuthorize("hasRole('ROLE_ADMIN')")
public class ApplicationController {
	
	private static Logger log = LoggerFactory.getLogger(ApplicationController.class);

	@Autowired
	private ApplicationService applicationService;
	
	@RequestMapping("/")
	public String getMessageFromService() {
		log.info("Inside ApplicationController.getMessageFromService() method");
		return applicationService.getMessage() + ", " + SecurityContextHolder.getContext().getAuthentication().getName() + "!";
	}
	
	@PostMapping("/")
	public String getMessageFromServiceSecure() {
		log.info("Inside ApplicationController.getMessageFromService() method");
		return applicationService.getMessage() + " " + SecurityContextHolder.getContext().getAuthentication().getName();
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
