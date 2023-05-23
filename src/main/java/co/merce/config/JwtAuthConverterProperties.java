package co.merce.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * This class reads JwtAuthConverterProperties from the application.yml file
 * @author bhavyag
 */
@Configuration
@ConfigurationProperties(prefix = "jwt.auth.converter")
public class JwtAuthConverterProperties {

    @Value("resource-id")
    private String resourceId;

    @Value("principal-attribute")
    private String principalAttribute;
    
    @Value("use-realm-role")
    private String useRealmRole;
    

    public String getResourceId() {
        return resourceId;
    }

    public void setResourceId(String resourceId) {
        this.resourceId = resourceId;
    }

    public String getPrincipalAttribute() {
        return principalAttribute;
    }

    public void setPrincipalAttribute(String principalAttribute) {
        this.principalAttribute = principalAttribute;
    }

	public String getUseRealmRole() {
		return useRealmRole;
	}

	public void setUseRealmRole(String useRealmRole) {
		this.useRealmRole = useRealmRole;
	}
    
    
}
