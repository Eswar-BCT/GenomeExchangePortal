package org.hudsonalpha.gep.service;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;
import com.amazonaws.services.cognitoidp.model.*;
import lombok.extern.slf4j.Slf4j;
import org.hudsonalpha.gep.config.CognitoConfig;
import org.hudsonalpha.gep.exception.DuplicateEmailException;
import org.hudsonalpha.gep.model.Login;
import org.hudsonalpha.gep.model.PasswordRequest;
import org.hudsonalpha.gep.model.ResetPasswordRequest;
import org.hudsonalpha.gep.model.Session;
import org.hudsonalpha.gep.model.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@Service
public class LoginService implements CognitoConfig
{
    private static final Logger logger = LoggerFactory.getLogger(LoginService.class);

    private final static String USERNAME = "USERNAME";

    private final static String PASSWORD = "PASSWORD";

    private final static String NEW_PASSWORD = "NEW_PASSWORD";

    protected static AWSCognitoIdentityProvider mIdentityProvider = null;

    public LoginService()
    {
        if (mIdentityProvider == null)
        {
            mIdentityProvider = getAmazonCognitoIdentityClient();
        }
    }

    protected AWSCognitoIdentityProvider getAmazonCognitoIdentityClient()
    {
        AWSCredentials credentials = getCredentials(cognitoID, cognitoKey);
        AWSCredentialsProvider credProvider = new AWSStaticCredentialsProvider(credentials);
        AWSCognitoIdentityProvider client = AWSCognitoIdentityProviderClientBuilder.standard()
                                                                                   .withCredentials(credProvider)
                                                                                   .withRegion(region)
                                                                                   .build();
        return client;
    }

    protected AWSCredentials getCredentials(String AWS_ID, String AWS_KEY)
    {
        AWSCredentials credentials = new BasicAWSCredentials(AWS_ID, AWS_KEY);
        return credentials;
    }

    public String createUser(final User userInfo) throws AWSCognitoIdentityProviderException
    {
        String emailAddr = userInfo.getEmail();
        if (emailAddr != null)
        {
            User info = findUserByEmail(emailAddr);
            if (info == null)
            {
                AdminCreateUserRequest cognitoRequest = new AdminCreateUserRequest()
                    .withUserPoolId(poolID)
                    .withUsername(userInfo.getUserName())
                    .withUserAttributes(
                        new AttributeType()
                            .withName(EMAIL)
                            .withValue(emailAddr),
                                /*new AttributeType()
                                        .withName(LOCATION)
                                        .withValue(userInfo.getLocation()),*/
                        new AttributeType()
                            .withName("email_verified")
                            .withValue("true")
                    );
                AdminCreateUserResult sd = mIdentityProvider.adminCreateUser(cognitoRequest);
                return sd.getSdkResponseMetadata().toString();
            }
            else
            {
                throw new DuplicateEmailException("The email address " + emailAddr + " is already in the database");
            }
        }
        return null;
    }

    public User findUserByEmail(String email)
    {
        User userInfo = null;
        if (email != null && email.length() > 0)
        {
            final String emailQuery = "email=\"" + email + "\"";
            ListUsersRequest usersRequest = new ListUsersRequest()
                .withUserPoolId(poolID)
                .withAttributesToGet(EMAIL, LOCATION)
                .withFilter(emailQuery);
            ListUsersResult usersRslt = mIdentityProvider.listUsers(usersRequest);
            List<UserType> users = usersRslt.getUsers();
            if (users != null && users.size() > 0)
            {
                if (users.size() == 1)
                {
                    UserType user = users.get(0);
                    final String userName = user.getUsername();
                    String emailAddr = null;
                    String location = null;
                    List<AttributeType> attributes = user.getAttributes();
                    if (attributes != null)
                    {
                        for (AttributeType attr : attributes)
                        {
                            if (attr.getName().equals(EMAIL))
                            {
                                emailAddr = attr.getValue();
                            }
                           /* else if (attr.getName().equals(LOCATION))
                            {
                                location = attr.getValue();
                            }*/
                        }
                        if (userName != null && emailAddr != null)
                        {
                            userInfo = new User(userName, emailAddr, location);
                        }
                    }
                }
                else
                {
                    throw new DuplicateEmailException("More than one user has the email address " + email);
                }
            }
        }
        return userInfo;
    }

    public void deleteUser(final String userName, final String password) throws AWSCognitoIdentityProviderException
    {
        Session sessionInfo = sessionLogin(userName, password);
        if (sessionInfo != null)
        {
            AdminDeleteUserRequest deleteRequest = new AdminDeleteUserRequest()
                .withUsername(userName)
                .withUserPoolId(poolID);
            mIdentityProvider.adminDeleteUser(deleteRequest);
        }
    }

    public Login userLogin(final String userName, final String password) throws AWSCognitoIdentityProviderException
    {
        logger.info("UserLogin in Config service class");
        Login loginInfo = null;
        Session sessionInfo = sessionLogin(userName, password);
        if (sessionInfo != null)
        {
            User userInfo = getUserInfo(userName);
            loginInfo = new Login(userInfo);
            loginInfo.setSession(sessionInfo);
            String challengeResult = sessionInfo.getChallengeResult();
            logger.info("challengeResult-->" + challengeResult);
            if (challengeResult != null && challengeResult.length() > 0)
            {
                loginInfo.setNewPasswordRequired(challengeResult.equals(ChallengeNameType.NEW_PASSWORD_REQUIRED.name()));
                logger.info("NewPasswordRequired -->" + loginInfo.getNewPasswordRequired());
            }
        }
        return loginInfo;
    }

    protected Session sessionLogin(final String userName, final String password) throws AWSCognitoIdentityProviderException
    {
        logger.info("SessionLogin in Config service class");
        Session info = null;
        HashMap<String, String> authParams = new HashMap<String, String>();
        authParams.put("USERNAME", userName);
        authParams.put("PASSWORD", password);
        AdminInitiateAuthRequest authRequest = new AdminInitiateAuthRequest()
            .withAuthFlow(AuthFlowType.ADMIN_NO_SRP_AUTH)
            .withUserPoolId(poolID)
            .withClientId(clientID)
            .withAuthParameters(authParams);
        AdminInitiateAuthResult authResult = mIdentityProvider.adminInitiateAuth(authRequest);
        logger.info("authResult -->" + authResult);
        if (authResult != null)
        {
            final String session = authResult.getSession();
            String accessToken = null;
            String refreshToken = null;
            AuthenticationResultType resultType = authResult.getAuthenticationResult();
            if (resultType != null)
            {
                accessToken = resultType.getAccessToken();
            }
            final String challengeResult = authResult.getChallengeName();
            logger.info("challengeResult -->" + challengeResult);
            info = new Session(session, accessToken, refreshToken, challengeResult);
        }
        return info;
    }

    public User getUserInfo(final String userName) throws AWSCognitoIdentityProviderException
    {
        logger.info("Get user info in config service class ");
        AdminGetUserRequest userRequest = new AdminGetUserRequest()
            .withUsername(userName)
            .withUserPoolId(poolID);
        AdminGetUserResult userResult = mIdentityProvider.adminGetUser(userRequest);
        logger.info("userResult --" + userResult);
        List<AttributeType> userAttributes = userResult.getUserAttributes();
        logger.info("userAttributes --" + userAttributes);
        final String rsltUserName = userResult.getUsername();
        String emailAddr = null;
        String location = null;
        for (AttributeType attr : userAttributes)
        {
            if (attr.getName().equals(EMAIL))
            {
                emailAddr = attr.getValue();
            }
            /*else if (attr.getName().equals(LOCATION))
            {
                location = attr.getValue();
            }*/
        }
        User info = null;

        if (rsltUserName != null && emailAddr != null)
        {
            info = new User(rsltUserName, emailAddr, location);
        }
        return info;
    }

    public void changePassword(final PasswordRequest passwordRequest) throws AWSCognitoIdentityProviderException
    {
        final Session sessionInfo = sessionLogin(passwordRequest.getUserName(), passwordRequest.getOldPassword());
        if (sessionInfo != null && sessionInfo.getAccessToken() != null)
        {
            ChangePasswordRequest changeRequest = new ChangePasswordRequest()
                .withAccessToken(sessionInfo.getAccessToken())
                .withPreviousPassword(passwordRequest.getOldPassword())
                .withProposedPassword(passwordRequest.getNewPassword());
            ChangePasswordResult rslt = mIdentityProvider.changePassword(changeRequest);
        }
        else
        {
            String msg = "Access token was not returned from session login";
            throw new AWSCognitoIdentityProviderException(msg);
        }
    }

    public void changeTemporaryPassword(final PasswordRequest passwordRequest) throws AWSCognitoIdentityProviderException
    {
        logger.info("changeTemporaryPassword in config service class");
        final Session sessionInfo = sessionLogin(passwordRequest.getUserName(), passwordRequest.getOldPassword());
        logger.info("sessionInfo--->" + sessionInfo);
        final String sessionString = sessionInfo.getSession();
        if (sessionString != null && sessionString.length() > 0)
        {
            Map<String, String> challengeResponses = new HashMap<String, String>();
            challengeResponses.put(USERNAME, passwordRequest.getUserName());
            challengeResponses.put(PASSWORD, passwordRequest.getOldPassword());
            challengeResponses.put(NEW_PASSWORD, passwordRequest.getNewPassword());
            AdminRespondToAuthChallengeRequest changeRequest = new AdminRespondToAuthChallengeRequest()
                .withChallengeName(ChallengeNameType.NEW_PASSWORD_REQUIRED)
                .withChallengeResponses(challengeResponses)
                .withClientId(clientID)
                .withUserPoolId(poolID)
                .withSession(sessionString);
            AdminRespondToAuthChallengeResult challengeResponse = mIdentityProvider.adminRespondToAuthChallenge(changeRequest);
        }
    }

    public void resetPassword(ResetPasswordRequest resetRequest) throws AWSCognitoIdentityProviderException
    {
        ConfirmForgotPasswordRequest passwordRequest = new ConfirmForgotPasswordRequest()
            .withUsername(resetRequest.getUserName())
            .withConfirmationCode(resetRequest.getResetCode())
            .withClientId(clientID)
            .withPassword(resetRequest.getNewPassword());
        ConfirmForgotPasswordResult rslt = mIdentityProvider.confirmForgotPassword(passwordRequest);
    }

    public void forgotPassword(final String userName) throws AWSCognitoIdentityProviderException
    {
        ForgotPasswordRequest passwordRequest = new ForgotPasswordRequest()
            .withClientId(clientID)
            .withUsername(userName);
        ForgotPasswordResult rslt = mIdentityProvider.forgotPassword(passwordRequest);
        CodeDeliveryDetailsType delivery = rslt.getCodeDeliveryDetails();
    }

    public User verifyToken(final String accessToken)
    {
        GetUserRequest request = new GetUserRequest().withAccessToken(accessToken);
        GetUserResult userResult = mIdentityProvider.getUser(request);
        List<AttributeType> userAttributes = userResult.getUserAttributes();
        logger.info("userAttributes --" + userAttributes);
        final String userName = userResult.getUsername();
        String emailAddr = null;
        for (AttributeType attr : userAttributes)
        {
            if (attr.getName().equals(EMAIL))
            {
                emailAddr = attr.getValue();
            }
        }
        User info = null;
        if (userName != null && emailAddr != null)
        {
            info = new User(userName, emailAddr, null);
        }
        return info;
    }

    public String oktaLogin(final String code)
    {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Accept", "application/json");
        headers.add("Authorization", "Basic " + base64Creds);
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        HttpEntity<String> request = new HttpEntity<String>(data + code, headers);
        RestTemplate restTemplate = new RestTemplate();
        try
        {
            return restTemplate.postForObject(accessTokenUrl, request, String.class);
        }
        catch (Exception e)
        {
            logger.error("Error occurred while login to Okta");
            e.printStackTrace();
        }
        return null;
    }

    public String verifyOktaAccessToken(final String accessToken)
    {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Accept", "application/json");
        headers.add("Authorization", "Basic " + base64Creds);
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        HttpEntity<Map<String, Object>> request = new HttpEntity(headers);
        RestTemplate restTemplate = new RestTemplate();
        try
        {
            return restTemplate.postForObject(verifyTokenUrl + accessToken + token_type_hint, request, String.class);
        }
        catch (Exception e)
        {
            logger.error("Error occurred while login to Okta");
            e.printStackTrace();
        }
        return null;
    }

    public String signOut(String accessToken)
    {
        AWSCognitoIdentityProvider cognitoClient = getAmazonCognitoIdentityClient();
        try
        {
            GlobalSignOutRequest globalSignOutRequest = new GlobalSignOutRequest().withAccessToken(accessToken);
            cognitoClient.globalSignOut(globalSignOutRequest);

            return "SUCCESS";
        }
        catch (Exception e)
        {
            e.printStackTrace();
            logger.error("Error occurred while signout");
        }
        return null;
    }
}
