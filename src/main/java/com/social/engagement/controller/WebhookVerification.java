package com.social.engagement.controller;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.social.engagement.utils.InstagramConstants;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
public class WebhookVerification {

	private final String TWITTER_CONSUMER_SECRET = "gAUztDbnOxh3ewCZdVSiUqpH8tPFcWHvywfpzBtJUVelSPEptE";

	@GetMapping("/twitter/callback/webhooks")
	public ResponseEntity<?> crcTwitter(@RequestParam(value = "crc_token") String crcToken) {

		String hash = null;

		log.info("----CRC Token from Twitter : {} and consumer_secret_key : {}", crcToken, TWITTER_CONSUMER_SECRET);
		try {
			Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
			SecretKeySpec secret_key = new SecretKeySpec(TWITTER_CONSUMER_SECRET.getBytes(), "HmacSHA256");
			sha256_HMAC.init(secret_key);
			hash = Base64.encodeBase64String(sha256_HMAC.doFinal(crcToken.getBytes()));
			log.info("----Hash Code that will be validated by twitter : {}", hash);

		} catch (Exception e) {
			throw new RuntimeException("----Use agaian exception and throw proper error msg.");
		}

		return ResponseEntity.status(HttpStatus.OK).body(new ModelMap().addAttribute("response_token", hash));
	}

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
	public void facebookDataStreamPage(HttpServletRequest request, String data) throws Exception {
		String pushedJsonAsString = IOUtils.toString(request.getInputStream(), "utf-8");
		log.info(" Event response : {}", pushedJsonAsString);

		JSONObject entries = (JSONObject) new JSONParser().parse(pushedJsonAsString);
		String object = (String) entries.get(InstagramConstants.OBJECT);
		log.info("----Object : {}", object);
		if (InstagramConstants.INSTAGRAM.equalsIgnoreCase(object)) {
			log.info("----Object is instagram object.-----");

		}

		log.info("------Event Response to be sent to datalake. : {}", entries);

	}
}
