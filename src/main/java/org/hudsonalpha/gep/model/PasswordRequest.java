package org.hudsonalpha.gep.model;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public class PasswordRequest
{
    private final String userName;

    private final String oldPassword;

    private final String newPassword;
}
