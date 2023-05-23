package co.merce.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * This class reads Keycloak related properties required for Keycloak Admin Client
 * @author bhavyag
 */
@Configuration
@ConfigurationProperties(prefix = "keycloak")
public class KeycloakProperties {

	private String realm;
	
	private String authServerUrl;
	
	private String sslRequired;
	
	private String resource;
	
	private String credentialsSecret;

	public String getRealm() {
		return realm;
	}

	public void setRealm(String realm) {
		this.realm = realm;
	}

	public String getAuthServerUrl() {
		return authServerUrl;
	}

	public void setAuthServerUrl(String authServerUrl) {
		this.authServerUrl = authServerUrl;
	}

	public String getSslRequired() {
		return sslRequired;
	}

	public void setSslRequired(String sslRequired) {
		this.sslRequired = sslRequired;
	}

	public String getResource() {
		return resource;
	}

	public void setResource(String resource) {
		this.resource = resource;
	}

	public String getCredentialsSecret() {
		return credentialsSecret;
	}

	public void setCredentialsSecret(String credentialsSecret) {
		this.credentialsSecret = credentialsSecret;
	}

	@Override
	public String toString() {
		return "KeycloakProperties [realm=" + realm + ", authServerUrl=" + authServerUrl + ", sslRequired="
				+ sslRequired + ", resource=" + resource + ", credentialsSecret=" + credentialsSecret + "]";
	}
	
	
	
}
