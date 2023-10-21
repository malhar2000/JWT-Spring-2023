package com.malhar.jwt.jwtauth.user;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/secure")
public class DemoController {

    @GetMapping
    @PreAuthorize("hasRole('USER')")
     public String secure(){
        return "Secure!!";
    }
}
