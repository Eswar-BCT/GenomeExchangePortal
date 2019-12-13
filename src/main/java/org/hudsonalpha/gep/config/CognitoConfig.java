package org.hudsonalpha.gep.config;

import java.util.Base64;

import com.amazonaws.regions.Regions;

public interface CognitoConfig
{
    public final static String EMAIL = "email";
    public final static String LOCATION = "custom:location";
    public final static String cognitoID = "AKIAYHGEEU5ONJB55E4J";// Cognito IAM ID
    public final static String cognitoKey = "KnZ1wIcF/bbVsOueOR1LK/p4tiFMte5BWe0CfSJk"; // Cognito IAM "secret key"
    public final static String poolID = "us-east-2_RC05FwBbw";
    public final static String clientID = "2ke75a7o7ttu0g55p7h3um6mh4";
    public final static Regions region = Regions.US_EAST_2; // Replace this with the AWS region for your application
    //For okta variables
    public final static String accessTokenUrl = "https://dev-574123.okta.com/oauth2/default/v1/token";
    public final static String redirect_uri = "http%3A%2F%2Flocalhost%3A9090%2Foktalogin";
    public final static String OktaClientID = "0oa2387f2xR4pQ6ug357";
    public final static String ClientsecretId = "deKZYkdtdtnhPje3oQAwp_zOH7-UkYXeSfIaLDiN";
    public final static String oktaCredentials = OktaClientID + ":" + ClientsecretId;
    public final static String base64Creds = Base64.getEncoder().encodeToString(oktaCredentials.getBytes());
    public final static String data = "grant_type=authorization_code&redirect_uri=" + redirect_uri + "&code=";
    public final static String verifyTokenUrl = "https://dev-574123.okta.com/oauth2/default/v1/introspect?token=";
    public final static String token_type_hint="&token_type_hint=access_token";

}
