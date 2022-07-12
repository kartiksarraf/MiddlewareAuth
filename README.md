# MiddlewareAuth

A Java Spring Boot Application that is configure to work as service provider as well as identity provider.

Working:

  When login request comes from actual service provider then this application work as a identity provider.
  Then for authenticate user it work as a service provider and send auth request to actual IDP (in our case it is Azure Active Directory).
  When AD authenticate user, it send auth response to this applciation.
  This application uses that response, and create its own auth response for actual service provider consider actual service provider auth request.
  Send that auth response to actual service provider, and hence user able to login to the system.

Framework:
  Spring Boot, Spring Security, Thymeleaf, Lombok, Swagger and Shibboleth
