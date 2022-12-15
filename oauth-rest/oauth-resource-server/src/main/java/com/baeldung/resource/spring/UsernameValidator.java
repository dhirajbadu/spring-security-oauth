package com.baeldung.resource.spring;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

public class UsernameValidator implements OAuth2TokenValidator<Jwt> {
    private final String preferredUsername;

    UsernameValidator(String preferredUsername) {
        this.preferredUsername = preferredUsername;
    }

    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        OAuth2Error error = new OAuth2Error("invalid_token", "The required audience is missing", null);
        String username = jwt.getClaim("preferred_username");

        if (username == null || username.trim().isEmpty()){
            return OAuth2TokenValidatorResult.failure(error);
        }

        if (username.endsWith(preferredUsername)) {
            return OAuth2TokenValidatorResult.success();
        }
        return OAuth2TokenValidatorResult.failure(error);
    }
}
