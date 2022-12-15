package com.baeldung.resource.spring;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

@Service
public class CustomAuthenticationManager implements AuthenticationManager {

    private final Log logger = LogFactory.getLog(this.getClass());
    private final JwtDecoder jwtDecoder;
    private Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthenticationConverter = new JwtAuthenticationConverter();

    public CustomAuthenticationManager(JwtDecoder jwtDecoder) {
        Assert.notNull(jwtDecoder, "jwtDecoder cannot be null");
        this.jwtDecoder = jwtDecoder;
    }

    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        BearerTokenAuthenticationToken bearer = (BearerTokenAuthenticationToken) authentication;
        Jwt jwt = this.getJwt(bearer);

        AbstractAuthenticationToken token = (AbstractAuthenticationToken) this.jwtAuthenticationConverter.convert(jwt);
        if (!jwt.getClaim("preferred_username").toString().endsWith("@test.com")) {
            throw new AuthenticationServiceException("the token does not contains valid email");
        }
        token.setDetails(bearer.getDetails());
        this.logger.debug("Authenticated token");
        return token;
    }

    private Jwt getJwt(BearerTokenAuthenticationToken bearer) {
        try {
            return this.jwtDecoder.decode(bearer.getToken());
        } catch (BadJwtException var3) {
            this.logger.debug("Failed to authenticate since the JWT was invalid");
            throw new InvalidBearerTokenException(var3.getMessage(), var3);
        } catch (JwtException var4) {
            throw new AuthenticationServiceException(var4.getMessage(), var4);
        }
    }
}
