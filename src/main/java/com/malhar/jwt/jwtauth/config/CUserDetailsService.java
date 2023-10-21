package com.malhar.jwt.jwtauth.config;

import com.malhar.jwt.jwtauth.user.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;

@Service
public class CUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AdminRepository adminRepository;

    @Autowired
    private AgentRepository agentRepository;

    private Role role;

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
        this.role = role;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // need to append ROLE_ (later to be use for hasRole, hasRole adds "ROLE_" automatically if we don;t
        // have thins it will cause problem)
        if(role == Role.ADMIN){
            Admin admin = adminRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("Admin Username " + username + "not found"));
            SimpleGrantedAuthority adminAuthority = new SimpleGrantedAuthority("ROLE_" +Role.ADMIN.name());
            Collection<GrantedAuthority> authorities = new ArrayList<>();
            authorities.add(adminAuthority);
            return new User(admin.getUsername(), admin.getPassword(), authorities);
        }else if(role == Role.AGENT){
            Agent agent = agentRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("Admin Username " + username + "not found"));
            SimpleGrantedAuthority agentAuthority = new SimpleGrantedAuthority("ROLE_" + Role.AGENT.name());
            Collection<GrantedAuthority> authorities = new ArrayList<>();
            authorities.add(agentAuthority);
            return new User(agent.getUsername(), agent.getPassword(), authorities);
        }else if(role == Role.USER){
            com.malhar.jwt.jwtauth.user.User user = userRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("Admin Username " + username + "not found"));
            SimpleGrantedAuthority userAuthority = new SimpleGrantedAuthority("ROLE_" + Role.USER.name());
            Collection<GrantedAuthority> authorities = new ArrayList<>();
            authorities.add(userAuthority);
            return new User(user.getUsername(), user.getPassword(), authorities);
        }
        return null;
    }
}
