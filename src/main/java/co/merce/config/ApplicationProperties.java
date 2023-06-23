package co.merce.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "application")
public class ApplicationProperties {

	private String corsAllowedOrigin;
	
	private String corsAllowedMethods;

	public String getCorsAllowedOrigin() {
		return corsAllowedOrigin;
	}

	public void setCorsAllowedOrigin(String corsAllowedOrigin) {
		this.corsAllowedOrigin = corsAllowedOrigin;
	}

	public String getCorsAllowedMethods() {
		return corsAllowedMethods;
	}

	public void setCorsAllowedMethods(String corsAllowedMethods) {
		this.corsAllowedMethods = corsAllowedMethods;
	}

	@Override
	public String toString() {
		return "ApplicationProperties [corsAllowedOrigin=" + corsAllowedOrigin + ", corsAllowedMethods="
				+ corsAllowedMethods + "]";
	}
}
