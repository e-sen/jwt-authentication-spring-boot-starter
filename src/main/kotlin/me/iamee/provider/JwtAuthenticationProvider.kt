package me.iamee.provider

import io.jsonwebtoken.JwtException
import me.iamee.JwtConfig
import me.iamee.token.JwtAuthenticationToken
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.web.authentication.session.SessionAuthenticationException

class JwtAuthenticationProvider(private val config: JwtConfig) : AuthenticationProvider {

    override fun authenticate(authentication: Authentication): Authentication {
        try {
            val token = authentication.credentials.toString()
            return JwtAuthenticationToken.create(token, config.getSigningKey())
        } catch (ex: JwtException) {
            throw SessionAuthenticationException(ex.message)
        }
    }

    override fun supports(authentication: Class<*>?): Boolean {
        return JwtAuthenticationToken::class.java.isAssignableFrom(authentication)
    }

}
