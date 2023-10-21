package com.malhar.jwt.jwtauth.user;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/agent")
public class AgentController {

    @Autowired
    private AgentService agentService;

    @PostMapping("/register")
    public void register(@RequestBody RegisterRequest request){
        System.out.println(request);
         agentService.register(request);
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request){
        AuthenticationResponse authResp = agentService.authenticate(request);
        if(authResp == null){
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(null);
        }
        return ResponseEntity.status(HttpStatus.OK).body(authResp);
    }

    @PatchMapping("/activate-agent")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> activateAgent(@RequestBody AgentActiveRequest activeRequest){
        agentService.activated(activeRequest);
        return ResponseEntity.status(HttpStatus.OK).body("Activated!");
    }

}
