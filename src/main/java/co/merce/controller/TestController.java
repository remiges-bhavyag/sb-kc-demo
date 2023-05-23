package co.merce.controller;


import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Test Controller. This class to be deleted before going live.
 * @author bhavyag
 */
@RestController
@RequestMapping("/test")
public class TestController {

	private static final Logger logger = LoggerFactory.getLogger(TestController.class);
	
	@GetMapping(value = "/anonymous")
	public ResponseEntity<String> getAnonymous() {
		logger.info("Hello from Anonymous");
		return ResponseEntity.ok("Hello from Anonymous");
	}

	//@PreAuthorize("hasRole('ROLE_USER')")
	@Secured("user")
	@GetMapping(value = "/user")
	public ResponseEntity<String> getUser(Principal principal) {
		logger.info("Hello form method User to user{} ",principal.getName());
		return ResponseEntity.ok("Hello form method User to User "+principal.getName());
	}

	@Secured("admin")
	@GetMapping(value = "/admin")
	public ResponseEntity<String> getAdmin(Principal principal) {
		logger.info("Hello from Admin");
		return ResponseEntity.ok("Hello from method Admin To user "+principal.getName());
	}

	@Secured({ "user", "admin" })
	@GetMapping(value = "/all-user")
	public ResponseEntity<String> getAllUser(Principal principal) {
		logger.info("Hello from All User");
		return ResponseEntity.ok("Hello from method All User to User "+principal.getName());
	}

}