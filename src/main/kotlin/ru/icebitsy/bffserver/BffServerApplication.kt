package ru.icebitsy.bffserver

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class BffServerApplication

fun main(args: Array<String>) {
	runApplication<BffServerApplication>(*args)
}
