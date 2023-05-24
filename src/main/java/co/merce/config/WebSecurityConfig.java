package co.merce.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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
        http.authorizeHttpRequests(requests -> requests.anyRequest().authenticated());
        http.oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthConverter))
                );
        http.sessionManagement(sessionManagement ->
			sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
				//.sessionConcurrency(sessionConcurrency ->
				//	sessionConcurrency
				//		.maximumSessions(1)
				//		.expiredUrl("/login?expired")
				//)
		);
        return http.build();
    }
	
	@Bean
	JwtDecoder jwtDecoder() {
		String jwkSetUri=kp.getAuthServerUrl()+"realms/"+kp.getRealm()+"/protocol/openid-connect/certs";
	    return NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
	}
}
