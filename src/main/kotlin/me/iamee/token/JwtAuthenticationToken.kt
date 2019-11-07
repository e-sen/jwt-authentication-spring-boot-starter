package me.iamee.token

import io.jsonwebtoken.Jwts
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority

class JwtAuthenticationToken : AbstractAuthenticationToken {

    var details: UserContext? = null

    var token: String? = null

    constructor(token: String) : super(null) {
        this.token = token
        this.isAuthenticated = false
    }

    constructor(details: UserContext, authorities: Collection<GrantedAuthority>) : super(authorities) {
        this.eraseCredentials()
        this.details = details
        this.isAuthenticated = true
    }

    override fun getCredentials(): Any? {
        return this.token
    }

    override fun getPrincipal(): Any? {
        return this.details
    }

    companion object {

        fun create(token: String, key: String): JwtAuthenticationToken {
            val claims = Jwts.parser().setSigningKey(key).parseClaimsJws(token).body
            val id = claims.id
            val username = claims.subject
            val scopes = claims.get("scopes", List::class.java)
            val authorities = scopes.map { SimpleGrantedAuthority(it as String) }.toMutableList()
            val context = UserContext().apply {
                this.id = id
                this.username = username
                this.authorities = authorities
            }
            return JwtAuthenticationToken(context, authorities)
        }

    }

}
