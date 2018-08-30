package com.revature.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.netflix.hystrix.contrib.javanica.annotation.HystrixCommand;

@Service
public class ApplicationService {

	@Value("${message:Hello World Spring Cloud Jwt}")
	private String message;
	
	@Value("${server.port:defaultValue}")
	private String port;
	
	@Value("${some.message:Default Message}")
	private String someMessage;
	
	@Value("${some.deep.property}")
	private String someDeepProperty;
	
	@HystrixCommand(fallbackMethod="fallback")
	public String getMessage() {
		return "Port " + this.port + ": " + this.message;
	}
	
	@HystrixCommand(fallbackMethod="fallback")
	public String getAnotherMessage() {
		return "This is being served at /api/app-service/another-endpoint";
	}
	
	@HystrixCommand(fallbackMethod="fallback")
	public String getSomeMessage() {
		return this.someMessage;
	}
	
	@HystrixCommand(fallbackMethod="fallback")
	public String getSomeDeepProperty() {
		return this.someDeepProperty;
	}
	
	public String fallback() {
		return "Fallback method invoked!";
	}
}
