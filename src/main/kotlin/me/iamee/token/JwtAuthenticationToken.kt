package me.iamee.token

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.impl.DefaultClaims
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import java.util.*

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

        fun create(
            id: String,
            username: String,
            authorities: MutableList<GrantedAuthority>,
            issuer: String,
            issuedAt: Date,
            expiredAt: Date,
            key: String
        ): String {
            val builder = Jwts.builder()

            val claims = DefaultClaims()
            claims.id = id
            claims.subject = username
            claims["scopes"] = authorities.map { it.authority }
            claims.expiration = expiredAt
            claims.issuedAt = issuedAt
            claims.issuer = issuer

            builder.setId(id)
            builder.setSubject(username)
            builder.setClaims(claims)
            builder.setIssuedAt(issuedAt)
            builder.setExpiration(expiredAt)
            builder.setIssuer(issuer)
            builder.signWith(SignatureAlgorithm.HS256, key)

            return builder.compact()
        }

    }

}
