package co.merce.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true, jsr250Enabled = true)
public class WebSecurityConfig {

	private final JwtAuthConverter jwtAuthConverter;

	public WebSecurityConfig(JwtAuthConverter jwtAuthConverter) {
		this.jwtAuthConverter = jwtAuthConverter;
	}
	
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		/*
		 * Authorization parameters to HTTP requests
		 */
		 
		http.authorizeHttpRequests()
				/*
				 * We can set Global Request-Role Matchers here. Following are some of the examples.
				 */
				// .requestMatchers(HttpMethod.GET, "/test/anonymous", "/test/anonymous/**").permitAll()
				// .requestMatchers(HttpMethod.GET, "/test/admin", "/test/admin/**").hasRole("admin")
				// .requestMatchers(HttpMethod.GET, "/test/user").hasAnyRole("user", "admin")
		
				/*
				 * Alternatively, these can be set directly on the methods. In case you want to
				 * use Roles defined on methods, then you have to add @EnableMethodSecurity
				 * annotation
				 */
				.anyRequest().authenticated();

		/*
		 * Add JWT Auth Converter to extract the Roles from JWT
		 */
		http.oauth2ResourceServer().jwt().jwtAuthenticationConverter(jwtAuthConverter);

		/*
		 * Set HTTP session management policy
		 */
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

		/*
		 * Return the HTTP object
		 */
		return http.build();
	}
	
}
