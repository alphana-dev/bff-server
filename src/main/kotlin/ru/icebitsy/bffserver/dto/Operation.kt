package ru.icebitsy.bffserver.dto

import org.springframework.http.HttpMethod

/**
 * Универсальный объект-контейнер, которое BFF получает из клиентского приложения (angular, react)
 * в полях указаны данные - какой адрес нужно вызвать, каким методом, какой body добавить
 * т.е. BFF просто использует эти данные для вызова конкретного Resource Server (из поля url) и также добавляет access token в запрос
 */
data class Operation (
    val httpMethod: HttpMethod,
    val url: String,
    val body: Any? = null
)