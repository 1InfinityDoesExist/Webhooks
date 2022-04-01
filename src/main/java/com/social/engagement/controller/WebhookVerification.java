package com.social.engagement.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class WebhookVerification {

	@GetMapping("/webhooks/verification")
	public ResponseEntity<?> registeringCallbackUrlForSubscription(@RequestParam(value = "hub.mode") String mode,
			@RequestParam(value = "hub.verify_token") String verify_token,
			@RequestParam(value = "hub.challenge") String challenge) {
		if (mode.equalsIgnoreCase("subscribe") && verify_token.equalsIgnoreCase("token")) {
			return ResponseEntity.status(HttpStatus.OK).body(challenge);
		}
		return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Challenge Failed");
	}
}
