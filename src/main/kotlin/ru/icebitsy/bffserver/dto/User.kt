package ru.icebitsy.bffserver.dto

/**
 * Полные данные профиля пользователя, которые получаем из сервера авторизации (keycloak)
 * можно добавлять и любые другие поля, в соответствии с бизнес процессами
 * для нашего функционала хватает и этих полей
 * пригодится для отображения в frontend
 */
data class User (
    val id: String? = null,
    val username: String? = null,
    val email: String? = null // можно добавлять любые поля, которые вам необходимы (из keycloak или другого Auth Server)
)