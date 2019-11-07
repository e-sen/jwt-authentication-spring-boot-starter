package me.iamee

import me.iamee.config.JwtAuthenticationSecurityConfig
import me.iamee.filter.JwtAuthenticationProcessFilter
import me.iamee.provider.JwtAuthenticationProvider
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.security.web.util.matcher.RequestMatcher

@Configuration
class JwtAuthenticationAutoConfiguration(
    private val config: JwtConfig
) {

    @Bean(name = ["jwt-provider"])
    fun provider(): AuthenticationProvider {
        return JwtAuthenticationProvider(config)
    }

    @Bean(name = ["jwt-filter"])
    fun filer(
        @Qualifier("jwt-manager") manager: AuthenticationManager,
        @Qualifier("jwt-failed-handler") handle: AuthenticationFailureHandler,
        @Qualifier("jwt-matcher") matcher: RequestMatcher
    ): AbstractAuthenticationProcessingFilter {
        return JwtAuthenticationProcessFilter(
            config = config,
            authenticationManager = manager,
            failed = handle,
            matcher = matcher
        )
    }

    @Bean(name = ["jwt-security-config"])
    fun securityConfig(@Qualifier("jwt-provider") provider: AuthenticationProvider, @Qualifier("jwt-filter") filter: AbstractAuthenticationProcessingFilter): JwtAuthenticationSecurityConfig {
        return JwtAuthenticationSecurityConfig(provider, filter)
    }

}
