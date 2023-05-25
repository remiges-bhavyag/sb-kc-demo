package co.merce.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true, jsr250Enabled = true)
public class WebSecurityConfig {

	private final JwtAuthConverter jwtAuthConverter;

	private final KeycloakProperties kp;
	
	public WebSecurityConfig(JwtAuthConverter jwtAuthConverter, KeycloakProperties keycloakProperties) {
		this.jwtAuthConverter = jwtAuthConverter;
		this.kp=keycloakProperties;
	}
	
	@Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(requests -> requests
        		/*
                 * We can set Global Request-Role Matchers here. Following are some of the examples.
                 */
        		//.requestMatchers(HttpMethod.GET, "/test/admin", "/test/admin/**").hasRole("admin")
        		//.requestMatchers(HttpMethod.GET, "/test/user").hasAnyRole("user", "admin")
        		//.requestMatchers(HttpMethod.GET, "/test/anonymous", "/test/anonymous/**").permitAll()
        		
        		/*
                 * Alternatively, these can be set directly on the methods. In case you want to
                 * use Roles defined on methods, then you have to add @EnableMethodSecurity
                 * annotation
                 */
        		.anyRequest()
        		.authenticated()
        		);
        
        /*
         * Add JWT Auth Converter to extract the Roles from JWT
         */
        http.oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthConverter))
                );
        /*
         * Set HTTP session management policy
         */
        http.sessionManagement(sessionManagement ->
			sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			/**
			 * Following policies can be set if need be
			 */
				//.sessionConcurrency(sessionConcurrency ->
				//	sessionConcurrency
				//		.maximumSessions(1)
				//		.expiredUrl("/login?expired")
				//)
		);
        /*
         * Return the HTTP object
         */
        return http.build();
    }
	
	@Bean
	JwtDecoder jwtDecoder() {
		String jwkSetUri=kp.getAuthServerUrl()+"realms/"+kp.getRealm()+"/protocol/openid-connect/certs";
	    return NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
	}
}
