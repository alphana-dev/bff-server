@file:Suppress("unused")

package ru.icebitsy.bffserver.controller

import com.fasterxml.jackson.core.JsonProcessingException
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import org.json.JSONException
import org.json.JSONObject
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.*
import org.springframework.util.LinkedMultiValueMap
import org.springframework.util.MultiValueMap
import org.springframework.web.bind.annotation.*
import org.springframework.web.client.HttpClientErrorException
import org.springframework.web.client.RestTemplate
import org.springframework.web.util.UriComponentsBuilder
import ru.icebitsy.bffserver.dto.Operation
import ru.icebitsy.bffserver.dto.User
import ru.icebitsy.bffserver.utils.CookieUtils
import java.util.*

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
class BFFController(private val cookieUtils: CookieUtils,
                    // статичный секрет, который используется для grant type = authorization code
                    @Value("\${keycloak.secret}")
                    private val clientSecret: String, 
                    @Value("\${keycloak.url}")
                    private val keyCloakURI: String,
                    @Value("\${client.url}")
                    private val clientURL: String,
                    @Value("\${keycloak.clientid}")
                    private val clientId: String,
                    // названия для вызова нужных grant types
                    @Value("\${keycloak.granttype.code}")
                    private val grantTypeCode: String,
                    @Value("\${keycloak.granttype.refresh}")
                    private val grantTypeRefresh: String): BFFControllerApi {

    // срок годности куков
    private var accessTokenDuration = 0
    private var refreshTokenDuration = 0

    // временно хранят значения токенов
    private var accessToken: String? = null
    private var idToken: String? = null
    private var refreshToken: String? = null

    // используется, чтобы получать любые значения пользователя из JSON
    private var payload: JSONObject? = null

    /**
     * Для получения статистики - отдельный метод
     * перенаправляет запрос в Resource Server и добавляет в него access token
     */
    @PostMapping("/stat")
    override fun stat(
        @RequestBody operation: Operation,
        @RequestBody email: String?,
        @CookieValue("AT") accessToken: String?
    ): ResponseEntity<Any> {

        // заголовок авторизации с access token
        val headers = HttpHeaders()
        headers.setBearerAuth(accessToken!!) // слово Bearer будет добавлено автоматически

        // специальный контейнер для передачи объекта внутри запроса
        val request = HttpEntity<Any>(email, headers)

        // получение бизнес-данных пользователя (ответ обернется в DataResult)
        return restTemplate.postForEntity(operation.url + "/stat", request, Any::class.java)
    }

    /**
     * Универсальный метод, который перенаправляет любой запрос из frontend на Resource Server и добавляет в него токен из кука
     */
    @PostMapping("/operation")
    override fun data(
        @RequestBody operation: Operation,
        @CookieValue("AT") accessToken: String?
    ): ResponseEntity<Any> {

        // заголовок авторизации с access token
        val headers = HttpHeaders()
        headers.setBearerAuth(accessToken!!) // слово Bearer будет добавлено автоматически
        headers.contentType = MediaType.APPLICATION_JSON // чтобы передать searchValues в формате JSON

        // специальный контейнер для передачи объекта внутри запроса
        val request = if (operation.body != null) {
            HttpEntity(operation.body, headers)
        } else {
            HttpEntity<Any>(headers)
        }

        // получение бизнес-данных пользователя (ответ обернется в DataResult)
        return restTemplate.exchange(operation.url, operation.httpMethod, request, Any::class.java)
    }

    /**
     * Получение новых токенов на основе старого RT
     */
    @GetMapping("/exchange")
    override fun exchangeRefreshToken(@CookieValue("RT") oldRefreshToken: String?): ResponseEntity<String> {
        val headers = HttpHeaders()
        headers.contentType = MediaType.APPLICATION_FORM_URLENCODED

        // параметры запроса (в формате ключ-значение)
        val mapForm = LinkedMultiValueMap<String, String>()
        mapForm.add("grant_type", grantTypeRefresh)
        mapForm.add("scope", "openid")
        mapForm.add("client_id", clientId)
        mapForm.add("client_secret", clientSecret)
        mapForm.add("refresh_token", oldRefreshToken)

        // собираем запрос для выполнения
        val request = HttpEntity<MultiValueMap<String, String>>(mapForm, headers)
        val response = restTemplate.exchange("$keyCloakURI/token", HttpMethod.POST, request, String::class.java)

        // сам response не нужно возвращать, нужно только оттуда получить токены
        parseResponse(response)

        // создаем куки для их записи в браузер (frontend)
        val responseHeaders = createCookies()

        // отправляем клиенту ответ со всеми куками (которые запишутся в браузер автоматически)
        // значения куков с новыми токенами перезапишутся в браузер
        return ResponseEntity.ok().headers(responseHeaders).build()
    }

    /**
     * Получение подробных данных пользователя (профайл)
     * все данные берем из ранее полученного idToken (передается в cookie, который можно прочитать только на сервере)
     * запроса в RS не делаем, т.к. бизнес-данные тут не запрашиваются
     */
    @GetMapping("/profile")
    override fun profile(@CookieValue("IT") idToken: String?): ResponseEntity<User> {

        // если переменная пустая - значит токен не был получен из кука, и мы не можем предоставлять данные пользователя
        if (idToken == null) {
            throw  HttpClientErrorException(HttpStatus.NOT_ACCEPTABLE, "access token not found")
            //return ResponseEntity<Any?>("access token not found", HttpStatus.NOT_ACCEPTABLE)
        }

        // можно запрашивать любые доп. данные из KC, если не хватает данных из ID Token
        // в нашем случае не требуется доп. запроса в KC, поэтому просто "парсим" готовый ID Token
        val userProfile = User(
            getPayloadValue("sid"),
            getPayloadValue("given_name"),
            getPayloadValue("email")
        )
        return ResponseEntity.ok(userProfile)
    }

    /**
     * Удаление сессий пользователя внутри KeyCloak и также зануление всех куков
     * этот метод не вызывает Resource Server, а напрямую обращается к KeyCloak, чтобы очистить сессии
     */
    @GetMapping("/logout_user")
    override fun logout(@CookieValue("IT") idToken: String?): ResponseEntity<String> {

        // 1. закрыть сессии в KeyCloak для данного пользователя
        // 2. занулить куки в браузере

        // чтобы корректно выполнить GET запрос с параметрами - применяем класс UriComponentsBuilder
        val urlTemplate: String = UriComponentsBuilder.fromHttpUrl("$keyCloakURI/logout")
            .queryParam("post_logout_redirect_uri", "{post_logout_redirect_uri}")
            .queryParam("id_token_hint", "{id_token_hint}")
            .queryParam("client_id", "{client_id}")
            .encode()
            .toUriString()

        // конкретные значения, которые будут подставлены в параметры GET запроса
        val params: MutableMap<String, String?> = HashMap()
        params["post_logout_redirect_uri"] = clientURL // может быть любым, т.к. frontend получает ответ от BFF, а не напрямую от Auth Server
        params["id_token_hint"] = idToken // idToken указывает Auth Server, для кого мы хотим "выйти"
        params["client_id"] = clientId

        // выполняем запрос (результат нам не нужен)
        restTemplate.getForEntity(
            urlTemplate,  // шаблон GET запроса - туда будут подставляться значения из params
            String::class.java,  // нам ничего не возвращается в ответе, только статус, поэтому можно указать String
            params // какие значения будут подставлены в шаблон GET запроса
        )


        // занулить значения и сроки годности всех куков (тогда браузер их удалит автоматически)
        val responseHeaders = clearCookies()

        // отправляем браузеру ответ с пустыми куками для их удаления (зануления), т.к. пользователь вышел из системы
        return ResponseEntity.ok().headers(responseHeaders).build()
    }

    /**
     * Удаление сессий пользователя внутри KeyCloak и также зануление всех куков
     * этот метод не вызывает Resource Server, а напрямую обращается к KeyCloak, чтобы очистить сессии
     */
    @GetMapping("/logout2")
    override fun logout2(@CookieValue("AT") accessToken: String,@CookieValue("RT") refreshToken: String): ResponseEntity<String> {
        println("logout2")
        val headers = HttpHeaders()
        headers.contentType = MediaType.APPLICATION_FORM_URLENCODED
        headers.setBearerAuth(accessToken)

        // параметры запроса (в формате ключ-значение)
        val mapForm = LinkedMultiValueMap<String, String>()
        //        mapForm.add("grant_type", grantTypeRefresh);
        mapForm.add("client_id", clientId)
        mapForm.add("client_secret", clientSecret)
        mapForm.add("refresh_token", refreshToken)

        // собираем запрос для выполнения
        val request =  HttpEntity<MultiValueMap<String, String>>(mapForm, headers)
        /*val response = */
        restTemplate.exchange("$keyCloakURI/logout", HttpMethod.POST, request, String::class.java)

        // сам response не нужно возвращать, нужно только оттуда получить токены
        // parseResponse(response);

        // создаем куки для их записи в браузер (frontend)
        val responseHeaders = clearCookies()

        // отправляем клиенту ответ со всеми куками (которые запишутся в браузер автоматически)
        // значения куков с новыми токенами перезапишутся в браузер
        return ResponseEntity.ok().headers(responseHeaders).build()
    }

    /**
     * Получение всех токенов и запись в куки
     * сами токены сохраняться в браузере не будут, а только будут передаваться в куках
     * таким образом к ним не будет доступа из кода браузера (защита от XSS атак)
     */
    @PostMapping("/token")
    override fun token(@RequestBody code: String): ResponseEntity<String> { // получаем auth code, чтобы обменять его на токены

        // 1. обменять auth code на токены
        // 2. сохранить токены в защищенные куки
        val headers = HttpHeaders()
        headers.contentType = MediaType.APPLICATION_FORM_URLENCODED

        // параметры запроса
        val mapForm = LinkedMultiValueMap<String, String>()
        mapForm.add("grant_type", grantTypeCode)
        mapForm.add("scope", "openid")
        mapForm.add("client_id", clientId)
        mapForm.add(
            "client_secret",
            clientSecret
        ) // используем статичный секрет (можем его хранить безопасно), вместо code verifier из PKCE
        mapForm.add("code", code)

        // В случае работы клиента через BFF - этот redirect_uri может быть любым, т.к. мы не открываем окно вручную, а значит не будет автоматического перехода в redirect_uri
        // Клиент получает ответ в объекте ResponseEntity
        // НО! Значение все равно передавать нужно, без этого grant type не сработает и будет ошибка.
        // Значение обязательно должно быть с адресом и портом клиента, например https://localhost:8080  иначе будет ошибка Incorrect redirect_uri, потому что изначально запрос на авторизацию выполнялся именно с адреса клиента
        mapForm.add("redirect_uri", clientURL)

        // добавляем в запрос заголовки и параметры
        val request: HttpEntity<MultiValueMap<String, String>> =
            HttpEntity<MultiValueMap<String, String>>(mapForm, headers)

        // выполняем запрос
        val response = restTemplate.exchange("$keyCloakURI/token", HttpMethod.POST, request, String::class.java)
        // мы получаем JSON в виде текста

        // сам response не нужно возвращать, нужно только оттуда получить токены
        parseResponse(response)

        // считать данные из JSON и записать в куки
        val responseHeaders = createCookies()

        // отправляем клиенту данные пользователя (и jwt-кук в заголовке Set-Cookie)
        return ResponseEntity.ok().headers(responseHeaders).build()
    }

    // получить любое значение claim из payload
    private fun getPayloadValue(claim: String): String? {
        return try {
            payload?.getString(claim)
        } catch (e: JSONException) {
            throw RuntimeException(e)
        }
    }

    // получение нужных полей из ответа KC
    private fun parseResponse(response: ResponseEntity<String>) {
        // парсер JSON
        val mapper = ObjectMapper()

        // сначала нужно получить корневой элемент JSON
        try {
            val root: JsonNode = mapper.readTree(response.body)

            // получаем значения токенов из корневого элемента JSON в формате Base64
            accessToken = root["access_token"].asText()
            idToken = root["id_token"].asText()
            refreshToken = root["refresh_token"].asText()

            // Сроки действия для токенов берем также из JSON
            // Куки станут неактивные в то же время, как выйдет срок действия токенов в KeyCloak
            accessTokenDuration = root["expires_in"].asInt()
            refreshTokenDuration = root["refresh_expires_in"].asInt()

            // все данные пользователя (профайл)
            val payloadPart = idToken?.split(".")?.toTypedArray()?.get(1) // берем значение раздела payload в формате Base64
            val payloadStr =  String(Base64.getUrlDecoder().decode(payloadPart)) // декодируем из Base64 в обычный текст JSON
            payload = JSONObject(payloadStr) // формируем удобный формат JSON - из него теперь можно получать любе поля
        } catch (e: JsonProcessingException) {
            throw RuntimeException(e)
        } catch (e: JSONException) {
            throw RuntimeException(e)
        }
    }

    // создание куков для response
    private fun createCookies(): HttpHeaders {

        // создаем куки, которые браузер будет отправлять автоматически на BFF при каждом запросе
        val accessTokenCookie: HttpCookie =
            cookieUtils.createCookie(ACCESSTOKEN_COOKIE_KEY, accessToken!!, accessTokenDuration)
        val refreshTokenCookie: HttpCookie =
            cookieUtils.createCookie(REFRESHTOKEN_COOKIE_KEY, refreshToken!!, refreshTokenDuration)
        val idTokenCookie: HttpCookie =
            cookieUtils.createCookie(IDTOKEN_COOKIE_KEY, idToken!!, accessTokenDuration) // задаем такой же срок, что и AT

        // чтобы браузер применил куки к бразуеру - указываем их в заголовке Set-Cookie в response
        val responseHeaders = HttpHeaders()
        responseHeaders.add(HttpHeaders.SET_COOKIE, accessTokenCookie.toString())
        responseHeaders.add(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString())
        responseHeaders.add(HttpHeaders.SET_COOKIE, idTokenCookie.toString())
        return responseHeaders
    }

    // зануляет все куки, чтобы браузер их удалил у себя
    private fun clearCookies(): HttpHeaders {
        // зануляем куки, которые отправляем обратно клиенту в response, тогда браузер автоматически удалит их
        val accessTokenCookie: HttpCookie = cookieUtils.deleteCookie(ACCESSTOKEN_COOKIE_KEY)
        val refreshTokenCookie: HttpCookie = cookieUtils.deleteCookie(REFRESHTOKEN_COOKIE_KEY)
        val idTokenCookie: HttpCookie = cookieUtils.deleteCookie(IDTOKEN_COOKIE_KEY)

        // чтобы браузер применил куки к браузеру - указываем их в заголовке Set-Cookie в response
        val responseHeaders = HttpHeaders()
        responseHeaders.add(HttpHeaders.SET_COOKIE, accessTokenCookie.toString())
        responseHeaders.add(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString())
        responseHeaders.add(HttpHeaders.SET_COOKIE, idTokenCookie.toString())
        return responseHeaders
    }

    companion object {
        // можно также использовать WebClient вместо RestTemplate, если нужны асинхронные запросы
        private val restTemplate = RestTemplate() // для выполнения веб запросов на KeyCloak

        // ключи для названий куков
        const val IDTOKEN_COOKIE_KEY = "IT"
        const val REFRESHTOKEN_COOKIE_KEY = "RT"
        const val ACCESSTOKEN_COOKIE_KEY = "AT"
    }
}