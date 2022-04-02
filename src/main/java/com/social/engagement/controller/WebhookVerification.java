package com.social.engagement.controller;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.io.IOUtils;
import org.json.simple.JSONArray;
import org.json.simple.parser.JSONParser;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
public class WebhookVerification {

	@GetMapping("/callback/webhooks")
	public ResponseEntity<?> registeringCallbackUrlForSubscription(@RequestParam(value = "hub.mode") String mode,
			@RequestParam(value = "hub.verify_token") String verify_token,
			@RequestParam(value = "hub.challenge") String challenge) {
		if (mode.equalsIgnoreCase("subscribe") && verify_token.equalsIgnoreCase("token")) {
			return ResponseEntity.status(HttpStatus.OK).body(challenge);
		}
		return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Challenge Failed");
	}

	/**
	 * Ready to receive events. like comment/like/post
	 * 
	 * @param request
	 * @param data
	 * @throws Exception
	 */
	@RequestMapping(value = "/callback/webhooks", method = RequestMethod.POST)
	public ResponseEntity<?> facebookDataStreamPage(HttpServletRequest request, String data) throws Exception {
		String pushedJsonAsString = IOUtils.toString(request.getInputStream(), "utf-8");
		log.info(" Event response : {}", pushedJsonAsString);
		log.info("------Data : {}", data);

		JSONArray entries = (JSONArray) new JSONParser().parse(pushedJsonAsString);
		return ResponseEntity.status(HttpStatus.OK).body(
				new ModelMap().addAttribute("pushedJsonAsString", pushedJsonAsString).addAttribute("entries", entries));

	}
}
