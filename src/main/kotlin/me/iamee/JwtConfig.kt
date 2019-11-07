package me.iamee

interface JwtConfig {

    fun getSigningKey(): String

    fun getHeaderParamKey(): String

    fun getHeaderPrefix(): String

}
