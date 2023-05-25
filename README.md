
# 1. What is Keycloak and How can It help me? {#1-what-is-keycloak-and-how-can-it-help-me}

Keycloak is an open-source identity and access management solution that provides authentication, authorization, and single sign-on capabilities for web applications and services. It allows you to secure your applications by managing user identities, enforcing access controls, and facilitating seamless user authentication across multiple systems.

Keycloak can help you in several ways:



1. **User Authentication**: Keycloak supports various authentication methods, including username/password, social login (e.g., Google, Facebook), and multi-factor authentication, allowing you to secure your application's login process.
2. **Authorization**: With Keycloak, you can define fine-grained access control policies based on roles, permissions, and user attributes. It enables you to manage user permissions and restrict access to certain resources within your application.
3. **Single Sign-On (SSO)**: Keycloak enables SSO, allowing users to authenticate once and access multiple applications or services without the need to re-enter credentials. It simplifies the user experience and improves security by reducing the number of passwords users need to remember.
4. **User Federation**: Keycloak supports user federation, which means you can integrate it with existing user directories or identity providers, such as LDAP, Active Directory, or social identity providers. This allows you to centralize user management and leverage existing user repositories.
5. **Client Integration**: Keycloak provides client libraries and adapters for various programming languages and frameworks, making it easier to integrate authentication and authorization capabilities into your applications.

Overall, Keycloak simplifies the implementation of secure authentication and access control in your applications, reduces development time, and improves overall security by providing a comprehensive identity and access management solution.

More details about keycloak and its capabilities are on Keycloak’s website [https://www.keycloak.org/](https://www.keycloak.org/)

Keycloak has API’s and Libraries that can help you write code in a variety of languages like Java, PHP, Python and others.

There are libraries for Frontend Scripting languages like Angular.

Keycloak itself is written in Java and is completely open source. Its code is hosted on Github. Details [https://github.com/keycloak/keycloak](https://github.com/keycloak/keycloak)

Its Javadocs are available for those who are interested. Details [https://www.keycloak.org/docs-api/21.1.1/javadocs/index.html](https://www.keycloak.org/docs-api/21.1.1/javadocs/index.html)

Keycloak also exposes a REST based Admin API via which all activities of Keycloak. Details [https://www.keycloak.org/docs-api/21.1.1/rest-api/index.html](https://www.keycloak.org/docs-api/21.1.1/rest-api/index.html)


# 2. How do I use keycloak to secure my application the Merce way? {#2-how-do-i-use-keycloak-to-secure-my-application-the-merce-way}

One approach to secure your **Spring/Spring Boot** applications is what we’ll discuss here.

There are a few pieces that we need to understand before we begin with this journey.

**Keycloak** supports multiple authorization frameworks including OpenID Connect, OAuth 2.0 and SAML 2.0.  (Ref: [https://www.keycloak.org/](https://www.keycloak.org/))

**OAuth2.0** ([https://auth0.com/intro-to-iam/what-is-oauth-2](https://auth0.com/intro-to-iam/what-is-oauth-2)) is an authorization framework that allows applications to access and use resources on behalf of a user without requiring the user to share their credentials (such as username and password) with the application. 

It provides a secure and standardized way for users to grant permissions to third-party applications to access their protected resources.

**Spring Security** is a powerful and highly customizable security framework for Java applications, specifically those built on the Spring framework. 

It provides a comprehensive set of features and APIs to handle authentication, authorization, and other security-related tasks in a Java application.

It is the de-facto standard for securing Spring-based applications. 

(Ref: [https://spring.io/projects/spring-security](https://spring.io/projects/spring-security))

So, we’ll now use our Spring boot based code with Spring Security using the OAuth2 Framework and Keycloak Server to secure our application.


---


## 2.1 Keycloak {#2-1-keycloak}


### 2.1.1 Downloading Keycloak {#2-1-1-downloading-keycloak}

Keycloak works on almost all Linux based distribution and windows. Installation instructions.

For our case, since most of us developers are on Ubuntu, we’ll proceed with Basic JDK based setup. 

[https://www.keycloak.org/getting-started/getting-started-zip](https://www.keycloak.org/getting-started/getting-started-zip)

Basic steps are:



1. Download the docker zip file.
2. Extract the zip file to some folder. (unzip keycloak-21.1.1.zip)
3. Start Keycloak. (bin/kc.sh start-dev)

Note that Keycloak by default starts on port **8080**. Ensure it's available.

Note: There are container images also available if you are comfortable with containers.

Docker: [https://www.keycloak.org/getting-started/getting-started-docker](https://www.keycloak.org/getting-started/getting-started-docker)

Kubernetes: [https://www.keycloak.org/getting-started/getting-started-kube](https://www.keycloak.org/getting-started/getting-started-kube)


### 2.1.2 Setting up Keycloak {#2-1-2-setting-up-keycloak}


#### 2.1.2.1 Creating Administrator user {#2-1-2-1-creating-administrator-user}



1. Open :  [http://localhost:8080/](http://localhost:8080/) <br>
![1](https://github.com/merce-bhavyag/sb-kc-demo/assets/121023504/a8710bed-6421-4bfe-a30f-3f2510942fcd)

2. Fill in the form with your preferred username and password.
3. Now go to the default admin console [http://localhost:8080/admin](http://localhost:8080/admin)

            And Login with username and password created earlier.


#### 2.1.2.2 Creating a Realm.  {#2-1-2-2-creating-a-realm}

A realm in Keycloak is equivalent to a tenant. Each realm allows an administrator to create isolated groups of applications and users. Initially, Keycloak includes a single realm, called _master_. Use this realm only for managing Keycloak and not for managing any applications.

Use these steps to create the first realm.



1. Open the [Keycloak Admin Console](http://localhost:8080/admin).
2. Click the word master in the top-left corner, then click Create realm.
3. Enter myrealm in the Realm name field.
4. Click Create.

Note: We’ll use Realm for a business application like HRMS/CBS etc.


#### 2.1.2.3 Creating a Keycloak Client. {#2-1-2-3-creating-a-keycloak-client}

A Keycloak client refers to an application or service that interacts with the Keycloak server to obtain authentication and authorization services. It represents a registered entity that wants to utilize Keycloak's features, such as user authentication, access control, and single sign-on. 

So, we can have a keycloak client for our Spring boot application, another client for say our PHP application and another client for say our Front end application.

Steps to create Keycloak Client are as follows:



1. Open the [Keycloak Admin Console](http://localhost:8080/admin).
2. Click on master on top right corner and select  myrealm
3. Click on ‘Clients’ in the menu bar on right
4. Click on ‘Create Client’ button
5. Fill in the details as following<br>
![2](https://github.com/merce-bhavyag/sb-kc-demo/assets/121023504/32478f2c-cfc5-4073-ae6e-22d9d50129c3)
6. Click on Next 
7. Enable Client Authentication, Authorization as following screenshot:<br>
![3](https://github.com/merce-bhavyag/sb-kc-demo/assets/121023504/39234771-0133-4ee2-a1d2-44a7ae4ff0ca)

8. Click on Save.
9. Now, if you go to the ‘Credentials’ tab you will see the client secret as follows:<br>
![4](https://github.com/merce-bhavyag/sb-kc-demo/assets/121023504/ac5d0cf1-d417-49f3-8475-6ee611c92966)
<br>
We’ll use this **‘Client secret’** while connecting to Keycloak.

You have now created a Keycloak Client for the spring boot app.


#### 2.1.2.4 Creating a Keycloak User {#2-1-2-4-creating-a-keycloak-user}

A keycloak user is the user who uses your application. Any user that will use your application, will have to be created in Keycloak. Keycloak will manage the user lifecycle.

Following are the steps to create a user in Keycloak:



1. Open the [Keycloak Admin Console](http://localhost:8080/admin).
2. Click on master on top right corner and select  myrealm
3. Click on ‘Users’ in the menu bar on the right
4. Click on the ‘Add user’ button.
5.  Fill in details as following:<br>
![5](https://github.com/merce-bhavyag/sb-kc-demo/assets/121023504/bcd3cc3e-d465-481c-b58d-3ffc968fc937)

<br>

    And Click on ‘Create’.

6. Now go to Credentials tab and click on ‘Set password’<br>

 ![6](https://github.com/merce-bhavyag/sb-kc-demo/assets/121023504/d5cc4e7c-0535-41e5-a0dd-26684da2c454)


<br>
7. Create a password for this user and click on Save<br>

 ![7](https://github.com/merce-bhavyag/sb-kc-demo/assets/121023504/5849198a-0fa1-49f3-8f6e-cc84f6193505)

<br>
You have now created a user called ‘myuser’ in Keycloak.



8. We’ll also create another user ‘myAdminUser’ using the same step as above.
9. So now, we will see two users:<br>

![8](https://github.com/merce-bhavyag/sb-kc-demo/assets/121023504/280572ab-2386-4e5e-9adb-e0280690b983)

<br>
#### 2.1.2.5 Setting Roles in Keycloak {#2-1-2-5-setting-roles-in-keycloak}

For the authorization part in our spring boot application, we’ll need to create different roles.

A role refers to a predefined set of permissions or access rights that can be assigned to users or clients. Roles are used to control and enforce authorization policies within the OAuth2 framework. 

By assigning roles to users or clients, you can determine what actions they are allowed to perform and what resources they can access.

There are roles to be created at two levels, Keycloak Client level and Keycloak Realm level.

We’ll create role roles at “myclient-sb” client which we created above and at our “myrealm” realm level.

Then we’ll convert our realm level role to a composite role so that whenever we create a user, we’ll just need to add one realm level role.



1. Create Client level role
    1. Open the [Keycloak Admin Console](http://localhost:8080/admin).
    2. Click on master on top right corner and select  myrealm
    3. Click on ‘Clients’ in the menu bar on right
    4. Now click on “myclient-sb” Client we previously created.
    5. Click on ‘Roles’ tab.
    6. Click on ‘Create role’ button.
    7. Add role name as ‘admin’<br>

        ![9](https://github.com/merce-bhavyag/sb-kc-demo/assets/121023504/604d1904-f84b-4bbf-8b0b-a72e44717c98)
<br>

    8. Click on Save.
    9. Now create another role ‘user’ using the same step as above.<br>
  ![10](https://github.com/merce-bhavyag/sb-kc-demo/assets/121023504/138b1a89-26c2-4f60-aa01-96a632089849)
  <br>
    10. Now under the client> Roles tab we can see 2 custom roles we created as follows: <br>
        ![11](https://github.com/merce-bhavyag/sb-kc-demo/assets/121023504/8d6c7b53-249c-4506-a522-ee0a1c3f435c)
        <br>

2. Create Realm level role
    1. Open the [Keycloak Admin Console](http://localhost:8080/admin).<br>
    2. Click on master on top right corner and select  myrealm<br>
    3. Click on ‘Realm roles’ in the menu bar on right<br>
    4. Click on ‘Create role’ button<br>
    5. Create a role ‘app-admin’ as follows:<br>

   ![12](https://github.com/merce-bhavyag/sb-kc-demo/assets/121023504/802602b2-096f-4c68-a752-98c70f994263)
<br>
    6. Click on save.<br>
    7. Create a role ‘app-user’ as follows:<br>

   ![13](https://github.com/merce-bhavyag/sb-kc-demo/assets/121023504/27daba3c-b751-4ccd-999d-d3c5399c85b2)
<br>

    8. Now, under Realm Roles, we can see 2 custom roles we created above as follows:<br>
   ![14](https://github.com/merce-bhavyag/sb-kc-demo/assets/121023504/fb1f786a-4852-4135-bc8c-82a8d8bf60ce)
<br>       
        Note in above screenshot, we can see that under “Composite” column, roles are termed as ‘False’, which means they are not a composite role at this point.

3. Convert Realm level role to a Composite role
    1. To convert Realm role to Composite role, we’ll select a role ‘app-admin’<br>
    2. Click on Action on top right corner and click on ‘Add associated roles’ as follows:<br>
   ![15](https://github.com/merce-bhavyag/sb-kc-demo/assets/121023504/46c8c5a7-3b88-40cc-a8ee-444c8b7b1413)
<br>

    3. Here, from the drop down, select ‘Filter by clients’ as follows:<br>

   ![16](https://github.com/merce-bhavyag/sb-kc-demo/assets/121023504/3c98da2e-f91b-475c-8fb2-f11d125041ab)


    4. And select ‘admin’ client level role we previously created as follows and click on ‘Assign’ button:<br>

   ![17](https://github.com/merce-bhavyag/sb-kc-demo/assets/121023504/7e0e27d4-47e4-496f-bd71-ac4d68578b3f)

<br>
    5. You can now see the role is now a Composite role, whereby the ‘Composite’ column is visible as ‘True’<br>
    
   ![18](https://github.com/merce-bhavyag/sb-kc-demo/assets/121023504/782fa417-59ab-49bd-b95d-b27d137774a8)
<br>
    6. We’ll repeat the steps for ‘app-user role to convert it to a composite role
    7. Click on the role ‘app-user’, Click on ‘Action’ on top right corner and select ‘Add associated roles’
    8. Select ‘Filter by clients’ in the drop down<br>
    
   ![19](https://github.com/merce-bhavyag/sb-kc-demo/assets/121023504/f55075d8-dd65-4d3c-b27c-bb984ebca063)
<br>
    9. Select client level role ‘user’<br>

![20](https://github.com/merce-bhavyag/sb-kc-demo/assets/121023504/e4ef14a0-a44b-42f1-9c41-e1b3dff3c69f)
<br>

    10. Click on Assign to save the role
    11. Now we can see both roles are composite role as follows:<br>

![21](https://github.com/merce-bhavyag/sb-kc-demo/assets/121023504/99596dfe-a7a4-4c52-af1c-01a1d698273a)



#### 2.1.2.6 Adding Role to the User {#2-1-2-6-adding-role-to-the-user}

We’ll now add the composite role we created to the user so that role will be a part of the user’s authorization parameters i.e. it’ll be a part of users Access Tokens.



1. Open the [Keycloak Admin Console](http://localhost:8080/admin).
2. Click on master on top right corner and select  myrealm
3. Click on ‘Users’ in the menu bar on the right
4. Select ‘myuser’ the user we previously created
5. Click on ‘Role mapping’ tab
6. Click on ‘Assign role’ button as follows<br>

    ![22](https://github.com/merce-bhavyag/sb-kc-demo/assets/121023504/9dc470a2-f1e6-4ce7-8061-7faa10954d4e)
<br>
7. Select ‘app-admin’ composite role we created in the previous step as follows:<br>

   ![23](https://github.com/merce-bhavyag/sb-kc-demo/assets/121023504/afa6ed26-70ad-45b5-8f60-925c528fb140)
<br>
8. Click on ‘Assign’ button to assign the role
9. Now you can see the role is assigned to the user ‘myuser’ under the ‘Role mapping’ tab <br>

   ![24](https://github.com/merce-bhavyag/sb-kc-demo/assets/121023504/42b6e8be-95d6-4ff1-b3c8-120c03737fd9)
<br>
10.  Now similarly using the same steps as above, we’ll add ‘app-admin’ role to user ‘myadminuser’<br>

   ![25](https://github.com/merce-bhavyag/sb-kc-demo/assets/121023504/e207dcb9-6aa3-4ad4-888c-9c5066e50e88)
<br>

We have now successfully configured Keycloak Users with associated roles.


---


## 2.2 Testing the Keycloak setup using Postman {#2-2-testing-the-keycloak-setup-using-postman}

I am assuming at this point that you have Postman app installed on your local machine. If not, please google the step to install Postman based on your device.

We’ll connect to Keycloak to fetch ‘Access token’.

I am attaching the Postman collection here for the reference. However, we’ll create a new connection as follows:<br>
   ![26](https://github.com/merce-bhavyag/sb-kc-demo/assets/121023504/af3ab83b-a76e-4f9e-8166-8f5df469a9cd)


<br>

Note the URL: [http://localhost:8080/realms/myrealm/protocol/openid-connect/token](http://localhost:8080/realms/myrealm/protocol/openid-connect/token)

Here: localhost : It is the host where Keycloak is running

         8080: Port on which Keycloak is listening

         ‘Myrealm’ is the realm we created above.

Following are the parameters which we add in the request body:



* client_id: ID of the keycloak client we created above
* client_secret : client secret generated by Keycloak [as seen in step 2.1.2.3 ]
* username : username of the userid trying to login to keycloak
* password : password of the userid 
* grant_type : this can be ‘client_credentials’ or ‘password’. We’ll use ‘password’
* scope : ‘openid’ 

If all configuration is correct, on sending this request, keycloak will respond with ‘access_token’ and ‘refresh_token’ alongwith expiry and other parameters.
<br>
   ![27](https://github.com/merce-bhavyag/sb-kc-demo/assets/121023504/77064393-3dba-4e08-b822-aeae4390d02d)
<br>

We’ll use this ‘access_token’ for all consecutive requests to authenticate ourself.

Pro-tip: You can check contents of this JWT token, using a site like ‘[http://jwt.io](http://jwt.io)’ Following is the example:<br>

   ![28](https://github.com/merce-bhavyag/sb-kc-demo/assets/121023504/3bff87bb-7f39-477b-afd4-bbf2ee9974b9)

<br>
As you can see in the above screenshot, under ‘resource_access’>’myclient-sb’>’roles’>’admin’

Here we can see the client name we created in Keycloak, along with the role of the user ‘admin’

We’ll use this role for the authorization part in the steps ahead.


---


## 2.3 Business application {#2-3-business-application}

We’ll now create a Spring boot application that will use Spring Security to secure the application via OAuth and it’ll work with Keycloak for Authentication and Role level Authorization.

You can find the entire working code on  Github link

 [ [https://github.com/merce-bhavyag/sb-kc-demo](https://github.com/merce-bhavyag/sb-kc-demo) ]

Go to [https://start.spring.io/](https://start.spring.io/) and we’ll get a new spring boot application<br>
   
   ![29](https://github.com/merce-bhavyag/sb-kc-demo/assets/121023504/0c7c304d-64a5-4946-ad3d-79da35dae0f3)
   <br>

And we’ll click on “GENERATE”

This will download a zip archive “sb-kc-demo-app.zip”

We’ll now use Either Eclipse or STS(Spring Tool Suite) to use this downloaded application.

For this guide, I’m using STS, but steps should be same for Eclipse.

Extract the ZIP file to a folder

Open STS, Click on File>’Open Projects from File System’ > Browse for the Zip file folder we downloaded from Spring Initilizr<br>
   ![30](https://github.com/merce-bhavyag/sb-kc-demo/assets/121023504/ac3ce207-6718-4b27-8967-a9ce59cb3d42)

<br>

So now, the application will open in the STS and will look as follows:<br>
   ![31](https://github.com/merce-bhavyag/sb-kc-demo/assets/121023504/552450e4-7c35-4039-9243-47977224d3dd)

<br>

We’ll create two packages ‘config’ and ‘controller’ within the ‘co.merce’ package

We’ll create config and controllers files under the respective packages<br>

   ![32](https://github.com/merce-bhavyag/sb-kc-demo/assets/121023504/116d0b04-4c02-478e-bcda-ad862ffbbebb)

<br>

We’ll create a new class ‘WebSecurityConfig.java’ under the config package.

 

This ‘WebSecurityConfig’ file will host all the configuration required for securing the springboot application.

We’ll add the following annotations to the class:


```
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true, jsr250Enabled = true)
```


@Configuration : Will mark the class as a configuration for spring boot.

@EnableWebSecurity : This will enable Spring Web Security for the application

@EnableMethodSecurity(securedEnabled = true, jsr250Enabled = true) : This will enable Method based security annotations and Spring will now look for “@Secured” annotation on methods and will secure the method accordingly.

Here we’ll add a bean to manage the HTTP requests the spring boot application will receive.


```
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
```


Here, if you note, we have our custom ‘jwtAuthConverter’ class that will extract the role information from the JWT token of the request.

Payload of a Decoded JWT token looks like this:

{

  "exp": 1684504093,

  "iat": 1684503793,

  "jti": "47fd2933-be33-4fba-bc98-2a83db11a80a",

  "iss": "http://localhost:8080/realms/myrealm",

  "aud": "account",

  "sub": "ead76933-6bd0-4618-b19d-b7ed31588e87",

  "typ": "Bearer",

  "azp": "myclient-sb",

  "session_state": "f1c96b22-70eb-4f4c-9e06-f10d28c2cd94",

  "acr": "1",

  "realm_access": {

    "roles": [

      "default-roles-myrealm",

      "offline_access",

      "app-admin",

      "uma_authorization"

    ]

  },

  "**resource_access**": {

    "myclient-sb": {

      "roles": [

        "**admin**"

      ]

    },

    "account": {

      "roles": [

        "manage-account",

        "manage-account-links",

        "view-profile"

      ]

    }

  },

  "scope": "openid profile email",

  "sid": "f1c96b22-70eb-4f4c-9e06-f10d28c2cd94",

  "email_verified": false,

  "name": "myadmin user",

  "preferred_username": "myadminuser",

  "given_name": "myadmin",

  "family_name": "user",

  "email": "myadminuser@merce.co"

}

From the above token, we need to extract roles of our client “myclient-sb” which falls under “resource_access”

Following is the method within the jwtAuthConverter that extracts roles as per above logic:


```
private Collection<? extends GrantedAuthority> extractResourceRoles(Jwt jwt) {
Map<String, Object> resourceAccess;
Map<String, Object> resource;
Collection<String> resourceRoles;
	resourceAccess = jwt.getClaim("resource_access");
	 if (resourceAccess == null
|| (resource = (Map<String, Object>) resourceAccess.get(properties.getResourceId())) == null
|| (resourceRoles = (Collection<String>) resource.get("roles")) == null) {
return Set.of();
}
return resourceRoles.stream()
.map(SimpleGrantedAuthority::new)
.collect(Collectors.toSet());
}
```


Of course there are other methods which we’ll need in this JwtConverter as follows:


```
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
```


And


```
private String getPrincipalClaimName(Jwt jwt) {
String claimName = JwtClaimNames.SUB;
if (properties.getPrincipalAttribute() != null) {
claimName = properties.getPrincipalAttribute();
}
return jwt.getClaim(claimName);
}
```


We’ll set the application.yml to set up the configuration as follows:<br>

   ![33](https://github.com/merce-bhavyag/sb-kc-demo/assets/121023504/c8f4bc3e-9c0e-477e-8bce-788641363746)
<br>

Ensure you set the correct client secret  [as seen in step 2.1.2.3 ] in “credentials.secret” parameter of application.yml

We’ll now create a TestController and secure the methods via the roles as follows:


```
@RestController
@RequestMapping("/test")
public class TestController {
	private static final Logger logger = LoggerFactory.getLogger(TestController.class);
	//@PreAuthorize("hasRole('ROLE_USER')")
	@Secured("user")
	@GetMapping(value = "/user")
	public ResponseEntity<String> getUser(Principal principal) {
		logger.info("Hello form method User to user{} ",principal.getName());
		return ResponseEntity.ok("Hello form method User to User "+principal.getName());
	}
	@Secured("admin")
	@GetMapping(value = "/admin")
	public ResponseEntity<String> getAdmin(Principal principal) {
		logger.info("Hello from Admin");
		return ResponseEntity.ok("Hello from method Admin To user "+principal.getName());
	}
	@Secured({ "user", "admin" })
	@GetMapping(value = "/all-user")
	public ResponseEntity<String> getAllUser(Principal principal) {
		logger.info("Hello from All User");
		return ResponseEntity.ok("Hello from method All User to User "+principal.getName());
	}
}
```


Now once we have everything set up, we can run the application and test if our authentication and authorization works.

Again, the entire code can be downloaded from the github repository

 [ [https://github.com/merce-bhavyag/sb-kc-demo](https://github.com/merce-bhavyag/sb-kc-demo) ]


---


## 2.4 Test Authentication and Authorization {#2-4-test-authentication-and-authorization}

We’ll use the Postman application to test this as we did in Step 2 before.

You can use the postman collection from the link below to test the setup.

[[https://github.com/merce-bhavyag/sb-kc-demo/blob/main/postman/Keycloak-Merce-Way.postman_collection.json](https://github.com/merce-bhavyag/sb-kc-demo/blob/main/postman/Keycloak-Merce-Way.postman_collection.json) ] 

This is how the test looks:<br>

   ![34](https://github.com/merce-bhavyag/sb-kc-demo/assets/121023504/10d8fde0-e45e-4dc8-8947-9eef8c3f4d5a)

<br>

We’ll pass the access_token to subsequent requests

So request to our endpoint “/admin” from myadminuser will work.<br>
   
   ![35](https://github.com/merce-bhavyag/sb-kc-demo/assets/121023504/e6f68742-6d4d-4b98-b7ba-b615400fb0e3)

<br>

However, the same request to endpoint “/user” will not work<br>

   ![36](https://github.com/merce-bhavyag/sb-kc-demo/assets/121023504/613e9728-d05e-4ab3-8887-934765b10bd0)
<br>

As we can see in the response as “403 Forbidden”

Similarly, access_token with user “myuser” will work with endpoint “/user” and will not work with endpoint “/admin”<br>

   ![37](https://github.com/merce-bhavyag/sb-kc-demo/assets/121023504/f19aff64-0b6b-40df-9ee2-ce6e13c52d75)


<br>

We’ll use this access_token to our request to endpoint “/user”<br>

   ![38](https://github.com/merce-bhavyag/sb-kc-demo/assets/121023504/6ba61399-2cb2-46a0-86e0-1f5559f78952)

<br>

We’ll get Forbidden error for endpoint “/admin”<br>

    ![39](https://github.com/merce-bhavyag/sb-kc-demo/assets/121023504/8c4272f5-2e5f-4f0c-a066-2f1dbd5878cb)

<br>

So, we have now secured our endpoints with correct roles along with authentication based on Oauth2 framework using Keycloak.
