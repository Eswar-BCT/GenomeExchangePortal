package org.hudsonalpha.gep.model;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public class User
{
    private final String userName;

    private final String email;

    private final String userStatus;
}
