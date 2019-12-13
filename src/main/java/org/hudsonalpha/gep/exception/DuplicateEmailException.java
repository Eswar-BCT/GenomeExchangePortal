package org.hudsonalpha.gep.exception;

import com.amazonaws.services.cognitoidp.model.AWSCognitoIdentityProviderException;

public class DuplicateEmailException extends AWSCognitoIdentityProviderException
{
    public DuplicateEmailException(final String errormessage)
    {
        super(errormessage);
    }
}
