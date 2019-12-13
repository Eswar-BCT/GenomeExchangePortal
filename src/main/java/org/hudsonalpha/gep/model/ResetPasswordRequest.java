package org.hudsonalpha.gep.model;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public class ResetPasswordRequest
{
    private final String userName;

    private final String resetCode;

    private final String newPassword;
}
