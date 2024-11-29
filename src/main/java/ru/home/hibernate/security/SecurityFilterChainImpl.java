package ru.home.hibernate.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@EnableWebSecurity
@Configuration
//@EnableMethodSecurity
public class SecurityFilterChainImpl {

    // User Creation
    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder encoder) {
        // InMemoryUserDetailsManager setup with two users
        UserDetails admin = User.withUsername("Admin")
                .password(encoder.encode("Admin"))
                .roles("DELETE")
                .build();

        UserDetails user = User.withUsername("User")
                .password(encoder.encode("User"))
                .roles("READ")
                .build();

        UserDetails superUser = User.withUsername("SuperUser")
                .password(encoder.encode("SuperUser"))
                .roles("WRITE")
                .build();

        UserDetails superAdmin = User.withUsername("SuperAdmin")
                .password(encoder.encode("SuperAdmin"))
                .roles("WRITE", "READ", "DELETE")
                .build();

        return new InMemoryUserDetailsManager(admin, user, superUser, superAdmin);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable) // Disable CSRF for simplicity
                .authorizeHttpRequests(auth -> auth
                                .anyRequest().authenticated()
//                        .requestMatchers("/persons/by-city").permitAll() // Permit all access to /persons/by-city
//                        .requestMatchers("/persons/by-age").authenticated() // Require authentication for /persons/by-age
//                        .requestMatchers("/persons/by-name-surname").hasAnyRole("ADMIN") // Require Role "ADMIN" for /persons/by-name-surname
                )
                .sessionManagement(withDefaults())
                .headers(withDefaults())
                .anonymous(withDefaults())
                .formLogin(withDefaults()); // Enable form-based login

        return http.build();
    }

    // Password Encoding
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
