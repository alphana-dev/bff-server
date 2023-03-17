package ru.icebitsy.bffserver.security

import org.springframework.beans.factory.annotation.Value
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.boot.autoconfigure.EnableAutoConfiguration
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration
import org.springframework.boot.autoconfigure.jdbc.DataSourceTransactionManagerAutoConfiguration
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import kotlin.Throws
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer
import org.springframework.web.servlet.config.annotation.CorsRegistry
import java.lang.Exception

@Configuration
@EnableWebSecurity(debug = false) // debug = true полезен при разработке для просмотра лога какие бины были созданы, в production нужно ставить false
// BFF не использует БД, поэтому отключаем автоконфигурацию датасорса (иначе сервер не будет стартовать, будет ошибка)
@EnableAutoConfiguration(exclude = [DataSourceAutoConfiguration::class, DataSourceTransactionManagerAutoConfiguration::class, HibernateJpaAutoConfiguration::class])
class SpringSecurityConfig(
    @Value("\${client.url}")
    private val clientURL: String // клиентский URL
) {

    // настройки безопасности для цепочки фильтров
    @Bean
    @Throws(Exception::class)
    fun filterChain(http: HttpSecurity): SecurityFilterChain {
        http.cors() // разрешает выполнять preflight запросы типа OPTIONS, чтобы они не блокировались и у них не проверялись токены
        // все сетевые настройки
        http.authorizeRequests()
            .anyRequest().permitAll() // остальной API будет доступен только аутентифицированным пользователям
            .and()
            .csrf().disable() // отключаем встроенную защиту от CSRF атак, т.к. используем свою, из OAUTH2
        http.requiresChannel().anyRequest().requiresSecure() // обязательное исп. HTTPS для всех запросах

        // отключаем создание куков для сессии (чтобы springboot сервер не создавал автоматически свои куки в браузере как statefull приложение)
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        return http.build()
    }

    // CORS настройка, чтобы разрешить запросы из других серверов, например из клиентского приложения
    // без этой настройки не будет работать BFF, потому что все входящие запросы будут просто блокироваться
    @Bean
    fun corsConfigurer(): WebMvcConfigurer {
        return object : WebMvcConfigurer {
            override fun addCorsMappings(registry: CorsRegistry) {
                registry.addMapping("/**") // для всех URL
                    .allowedOrigins(clientURL) // с каких адресов разрешать запросы
                    .allowCredentials(true) // разрешить отправлять куки для межсайтового запроса
                    .allowedHeaders("*") // разрешить все заголовки - без этой настройки в некоторых браузерах может не работать
                    .allowedMethods("*") // все методы разрешены (GET,POST и пр.) - без этой настройки CORS не будет работать!
            }
        }
    }
}