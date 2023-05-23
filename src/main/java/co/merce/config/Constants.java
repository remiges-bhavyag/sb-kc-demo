package co.merce.config;

/**
 * This file has all Constants to be used in the project
 * @author bhavyag
 */
public final class Constants {
	private Constants() {		
	}
	
	/**
	 * JWT Realm claim Key
	 */
	public static final String JWT_REALM_CLAIM="realm_access";
	
	/**
	 * JWT Resource claim key
	 */
	public static final String JWT_RESOURCE_CLAIM="resource_access";
	
	/**
	 * JWT key for role resource
	 */
	public static final String JWT_ROLE_RESOURCE="roles";
	
}
