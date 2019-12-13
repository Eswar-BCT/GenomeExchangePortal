package org.hudsonalpha.gep.model;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public class Session
{
    final private String session;

    final private String accessToken;

    final private String refreshToken;

    final private String challengeResult;
}
