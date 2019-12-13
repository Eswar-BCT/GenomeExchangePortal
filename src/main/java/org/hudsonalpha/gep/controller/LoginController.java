package org.hudsonalpha.gep.controller;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import com.amazonaws.services.cognitoidp.model.AWSCognitoIdentityProviderException;
import com.amazonaws.services.cognitoidp.model.InvalidParameterException;
import com.amazonaws.services.cognitoidp.model.InvalidPasswordException;
import com.amazonaws.services.cognitoidp.model.UserNotFoundException;
import lombok.extern.slf4j.Slf4j;
import org.hudsonalpha.gep.service.LoginService;
import org.hudsonalpha.gep.model.Login;
import org.hudsonalpha.gep.model.PasswordRequest;
import org.hudsonalpha.gep.model.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
public class LoginController
{
    private static final Logger logger = LoggerFactory.getLogger(LoginController.class);

    @Autowired
    private LoginService loginService;

    @PostMapping("/login")
    public Login login(@RequestParam("userName") String userName,
                       @RequestParam("password") String password)
    {
        try
        {
            logger.info("Login controller class");
            return loginService.userLogin(userName, password);
        }
        catch (AWSCognitoIdentityProviderException e)
        {
            logger.error("Error occurred in Login controller class");
            logger.info(e.getErrorMessage());
            e.printStackTrace();
        }
        return null;
    }

    @PostMapping("/loginFirst")
    public void LoginFirst(@RequestBody PasswordRequest passwordRequest)
    {
        try
        {
            loginService.changeTemporaryPassword(passwordRequest);
            logger.info("Password changed successfully");
        }
        catch (Exception e)
        {
            logger.error("Error occurred while changing pawwsord");
            e.printStackTrace();
        }
    }

    @GetMapping("/forgotpwd")
    public String forgotPassword(@RequestParam("userName") String userName)
    {
        try
        {
            loginService.forgotPassword(userName);
            logger.info("message", "A reset code has been sent to your email address");
        }
        catch (UserNotFoundException e)
        {
            logger.error("user_name_error", "Sorry, couldn't find the user " + userName);
        }
        catch (InvalidParameterException e)
        {
            logger.error("user_name_error", "Cannot reset password for the user as there is no registered/verified email or phone_number");
        }
        catch (Exception e)
        {
            e.printStackTrace();
            logger.error("user_name_error", "User name error: " + e.getClass().getName() + " " + e.getLocalizedMessage());
        }
        return "Password reset code has been sent to your email.";
    }

    @PostMapping("/changetempwd")
    public void changeTemporaryPassword(@RequestBody PasswordRequest passwordRequest)
    {
        try
        {
            loginService.changeTemporaryPassword(passwordRequest);
        }
        catch (
            InvalidPasswordException e)
        {
            logger.error("change_password_error", "Bad password error: " + e.getErrorMessage());
        }
        catch (Exception e)
        {
            logger.error("change_password_error", "Error encountered in changing password: " + e.getLocalizedMessage());
        }
    }

    @GetMapping("/verifytoken")
    public User verifyCognitoAccessToken(@RequestParam("access_token") String accessToken)
    {
        try
        {
            return loginService.verifyToken(accessToken);
        }
        catch (Exception e)
        {
            logger.error("Error occurred while verifying the token");
            e.printStackTrace();
        }
        return null;
    }

    @GetMapping("/oktalogin")
    public String oktaLogin(@RequestParam String code, HttpServletResponse response)
    {
        try
        {
            logger.info("okta Login code : " + code);
            String results = loginService.oktaLogin(code);
            String[] values = results.split(",");
            String accessToken = values[2].split(":")[1];
            logger.info("Results :" + results);

            Cookie cookie = new Cookie("access_token", accessToken.replace("\"", ""));
            response.addCookie(cookie);
            response.sendRedirect("http://localhost:9090/welcome.html");
            return results;
        }
        catch (Exception e)
        {
            logger.error("Error occurred while login to Okta");
            e.printStackTrace();
        }
        return null;
    }

    @GetMapping("/token")
    public String verifyOktaAccessToken(@RequestParam("access_token") String accessToken)
    {
        logger.info("Request accesstoken :" + accessToken);
        String results = loginService.verifyOktaAccessToken(accessToken);
        logger.info("result --->" + results);
        String[] values = results.split(",");
        String status = values[0].split(":")[1];
        return status.replace("}", "");
    }

    @GetMapping("/signout")
    public String signOut(@RequestParam("access_token") String accessToken,
                          @RequestParam("userName") String userName)
    {
        logger.info("User sign out request "+ userName);
        return loginService.signOut(accessToken);
    }

  /*  @PostMapping("/createuser")
    public String creatUser(@RequestBody User userInfo)
    {
        try
        {
            return loginService.createUser(userInfo);
        }
        catch (Exception e)
        {
            e.printStackTrace();
            logger.error("Exception occured while creating user");
        }
        return null;
    }

    @PostMapping("/resetpwd")
    public String resetPassword(@RequestParam("user_name") String userName,
                                @RequestParam("new_password") String newPassword,
                                @RequestParam("verify_password") String verifyPassword)
    {

        return "";
    }

    @PostMapping("/deleteuser")
    public String deleteUser(@RequestParam("user_name") String userName,
                             @RequestParam("new_password") String newPassword)
    {

        return "";
    }

    @PostMapping("/finduser")
    public String findUserByEmail(@RequestParam("user_name") String userName)
    {

        return "";
    }*/
}
