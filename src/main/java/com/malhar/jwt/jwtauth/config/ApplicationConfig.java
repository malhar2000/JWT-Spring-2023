package com.malhar.jwt.jwtauth.config;

import com.malhar.jwt.jwtauth.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
// easy way if you want you can make your own UserService class and extend UserDetailsService
public class ApplicationConfig {

    @Autowired
    private final UserRepository userRepository;

    @Autowired
    private final CUserDetailsService userDetailsService;

    // data access object which is imp for fetching userDetails
    // and also encode password
   @Bean
   public AuthenticationProvider authenticationProvider(){
       DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
       // tell which userDetailsService to use to fetch user
       authenticationProvider.setUserDetailsService(userDetailsService);
       authenticationProvider.setPasswordEncoder(passwordEncoder());
       return authenticationProvider;
   }

   @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // AuthenticationManager --> imp to manage authentication
    // AuthenticationConfiguration holds info about AuthenticationManager
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
         return configuration.getAuthenticationManager();
    }

}
