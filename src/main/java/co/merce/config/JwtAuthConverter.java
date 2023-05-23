package co.merce.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * This class helps in extracting roles from JWT claims and is used for authorization
 * @author bhavyag
 */
@Component
public class JwtAuthConverter implements Converter<Jwt, AbstractAuthenticationToken> {
	
	private static final Logger logger = LoggerFactory.getLogger(JwtAuthConverter.class);

    private final JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

    private final JwtAuthConverterProperties properties;

    public JwtAuthConverter(JwtAuthConverterProperties properties) {
        this.properties = properties;
    }

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
    	Collection<GrantedAuthority> a = jwtGrantedAuthoritiesConverter.convert(jwt);
    	Collection<? extends GrantedAuthority> b = extractResourceRoles(jwt);
    	Collection<GrantedAuthority> authorities;
    	if(a!=null) {
    		 authorities = Stream.concat(a.stream(),b.stream()).collect(Collectors.toSet());
    	}else {
    		authorities=b.stream().collect(Collectors.toSet());
    	}
        return new JwtAuthenticationToken(jwt, authorities, getPrincipalClaimName(jwt));
    }

    /**
     * Extract Principal Claim Attribute from JWT
     * @param jwt
     * @return
     */
    private String getPrincipalClaimName(Jwt jwt) {
        String claimName = JwtClaimNames.SUB;
        if (properties.getPrincipalAttribute() != null) {
            claimName = properties.getPrincipalAttribute();
        }
        return jwt.getClaim(claimName);
    }


    /**
     * This method extracts roles from the JWT token
     * @param jwt
     * @return Collection of Roles allowed
     */
	@SuppressWarnings("unchecked")
	private Collection<? extends GrantedAuthority> extractResourceRoles(Jwt jwt) {
        Map<String, Object> resourceAccess;
        Map<String, Object> resource;
        Collection<String> resourceRoles;

        /*
         * Check if role are to used from Realm level or Client level
         */
        if(Boolean.parseBoolean(properties.getUseRealmRole())) {
        	resourceAccess = jwt.getClaim(Constants.JWT_REALM_CLAIM);
        	if(resourceAccess==null 
        			|| (resourceRoles=(Collection<String>) resourceAccess.get(Constants.JWT_ROLE_RESOURCE))==null) {
            	return Set.of();
            }
        }else {
        	resourceAccess = jwt.getClaim(Constants.JWT_RESOURCE_CLAIM);
        	 if (resourceAccess == null
                     || (resource = (Map<String, Object>) resourceAccess.get(properties.getResourceId())) == null
                     || (resourceRoles = (Collection<String>) resource.get(Constants.JWT_ROLE_RESOURCE)) == null) {
                 return Set.of();
             }
        }
        if(logger.isDebugEnabled())
        	logger.debug("resourceRoles{}",resourceRoles);
        
        return resourceRoles.stream()
                //.map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());
    }
}