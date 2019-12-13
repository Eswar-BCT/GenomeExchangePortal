package org.hudsonalpha.gep.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Login extends User
{
    private Boolean newPasswordRequired = false;

    private Session session;

    public Login(final String userName, final String email, final String userStatus)
    {
        super(userName, email, userStatus);
    }

    public Login(final User info)
    {
        this(info.getUserName(), info.getEmail(), info.getUserStatus());
    }
}
