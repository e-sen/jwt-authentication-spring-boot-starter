package me.iamee.filter

import me.iamee.JwtConfig
import me.iamee.token.JwtAuthenticationToken
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.security.web.authentication.session.SessionAuthenticationException
import org.springframework.security.web.util.matcher.RequestMatcher
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class JwtAuthenticationProcessFilter(
    private val config: JwtConfig,
    authenticationManager: AuthenticationManager,
    private val failed: AuthenticationFailureHandler,
    private val matcher: RequestMatcher
) : AbstractAuthenticationProcessingFilter(matcher) {

    init {
        this.authenticationManager = authenticationManager
    }

    override fun attemptAuthentication(request: HttpServletRequest, response: HttpServletResponse): Authentication {
        val prefix = config.getHeaderPrefix()
        val header = request.getHeader(config.getHeaderParamKey()) ?: prefix
        val token = if (header.length <= prefix.length) {
            throw SessionAuthenticationException("token($header) is too short.")
        } else {
            header.substring(prefix.length)
        }
        return this.authenticationManager.authenticate(JwtAuthenticationToken(token = token))
    }

    override fun successfulAuthentication(
        request: HttpServletRequest,
        response: HttpServletResponse,
        chain: FilterChain,
        authResult: Authentication
    ) {
        val context = SecurityContextHolder.createEmptyContext()
        context.authentication = authResult
        SecurityContextHolder.setContext(context)
        chain.doFilter(request, response)
    }

    override fun unsuccessfulAuthentication(
        request: HttpServletRequest,
        response: HttpServletResponse,
        failed: AuthenticationException
    ) {
        this.failed.onAuthenticationFailure(request, response, failed)
    }

    override fun getFailureHandler(): AuthenticationFailureHandler {
        return this.failed
    }
}
