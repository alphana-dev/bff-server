package ru.icebitsy.bffserver.controller

import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import ru.icebitsy.bffserver.dto.Operation
import ru.icebitsy.bffserver.dto.User

/**
 * Адаптер между frontend и resource server - перенаправляет запросы между ними
 * Основная задача - сохранять токены в безопасных куках
 *
 * Сокращения:
 * AT - access token
 * RT - refresh token
 * IT - id token
 * RS - resource server
 * KC - keycloak
 **/
@RestController
interface BFFControllerApi {

    /**
     * Для получения статистики - отдельный метод
     * перенаправляет запрос в Resource Server и добавляет в него access token
     */
    @PostMapping("/stat")
    fun stat(
        @RequestBody operation: Operation,
        @RequestBody email: String?,
        @CookieValue("AT") accessToken: String?
    ): ResponseEntity<Any>

    /**
     * Универсальный метод, который перенаправляет любой запрос из frontend на Resource Server и добавляет в него токен из кука
     */
    @PostMapping("/operation")
    fun data(
        @RequestBody operation: Operation,
        @CookieValue("AT") accessToken: String?
    ): ResponseEntity<Any>

    /**
     * Получение новых токенов на основе старого RT
     */
    @GetMapping("/exchange")
    fun exchangeRefreshToken(@CookieValue("RT") oldRefreshToken: String?): ResponseEntity<String>

    /**
     * Получение подробных данных пользователя (профайл)
     * все данные берем из ранее полученного idToken (передается в cookie, который можно прочитать только на сервере)
     * запроса в RS не делаем, т.к. бизнес-данные тут не запрашиваются
     */
    @GetMapping("/profile")
    fun profile(@CookieValue("IT") idToken: String?): ResponseEntity<User>

    /**
     * Удаление сессий пользователя внутри KeyCloak и также зануление всех куков
     * этот метод не вызывает Resource Server, а напрямую обращается к KeyCloak, чтобы очистить сессии
     */
    @GetMapping("/logout_user")
    fun logout(@CookieValue("IT") idToken: String?): ResponseEntity<String>

    /**
     * Удаление сессий пользователя внутри KeyCloak и также зануление всех куков
     * этот метод не вызывает Resource Server, а напрямую обращается к KeyCloak, чтобы очистить сессии
     */
    @GetMapping("/logout2")
    fun logout2(
        @CookieValue("AT") accessToken: String,
        @CookieValue("RT") refreshToken: String
    ): ResponseEntity<String>

    /**
     * Получение всех токенов и запись в куки
     * сами токены сохраняться в браузере не будут, а только будут передаваться в куках
     * таким образом к ним не будет доступа из кода браузера (защита от XSS атак)
     */
    @PostMapping("/token")
    fun token(@RequestBody code: String): ResponseEntity<String>

}