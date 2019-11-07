package me.iamee.token

import com.fasterxml.jackson.annotation.JsonIgnore
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.userdetails.UserDetails

class UserContext : UserDetails {

    /**
     * 平台ID
     */
    var platform: String = "0000"

    /**
     * 用户ID
     */
    var id: String = "00000"

    /**
     * 用户名
     */
    private var username: String = ""

    fun setUsername(username: String) {
        this.username = username
    }

    /**
     * 密码
     */
    @JsonIgnore
    private var password: String = ""

    fun setPassword(password: String) {
        this.password = password
    }

    /**
     * 权限
     */
    private var authorities: MutableCollection<out GrantedAuthority> = arrayListOf()

    fun setAuthorities(authorities: MutableCollection<out GrantedAuthority>) {
        this.authorities = authorities
    }

    /**
     * 是否启用
     */
    private var enabled: Boolean = true

    /**
     * 密码未过期
     */
    private var credentialsNonExpired: Boolean = true

    /**
     * 账户未过期
     */
    private var accountNonExpired: Boolean = true

    /**
     * 账户未锁定
     */
    private var accountNonLocked: Boolean = true

    override fun getAuthorities(): MutableCollection<out GrantedAuthority> {
        return authorities
    }

    override fun isEnabled(): Boolean {
        return enabled
    }

    override fun getUsername(): String {
        return username
    }

    override fun isCredentialsNonExpired(): Boolean {
        return credentialsNonExpired
    }

    override fun getPassword(): String {
        return password
    }

    override fun isAccountNonExpired(): Boolean {
        return accountNonExpired
    }

    override fun isAccountNonLocked(): Boolean {
        return accountNonLocked
    }

    fun getUID(): String {
        return "$platform-$id"
    }
}
