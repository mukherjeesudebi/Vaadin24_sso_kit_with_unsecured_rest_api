package org.vaadin.example;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/test")
public class TestController {
	 @GetMapping("/unsecured")
	    public String unsecuredEndpoint() {
	        return "This endpoint is not secured with Azure login.";
	    }
}
