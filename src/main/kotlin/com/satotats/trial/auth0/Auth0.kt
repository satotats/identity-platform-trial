package com.satotats.trial.auth0

import com.auth0.jwk.JwkProviderBuilder
import io.ktor.application.*
import io.ktor.auth.*
import io.ktor.auth.jwt.*
import io.ktor.client.*
import io.ktor.client.engine.cio.*
import io.ktor.client.features.json.*
import io.ktor.client.features.json.serializer.*
import io.ktor.http.*
import io.ktor.response.*
import io.ktor.routing.*
import java.util.concurrent.TimeUnit


@Suppress("unused")
fun Application.main() {
    val httpClient = HttpClient(CIO) {
        install(JsonFeature) {
            serializer = KotlinxSerializer()
        }
    }

    val jwkProvider = JwkProviderBuilder(System.getenv("AUTH0_CLIENT_DOMAIN"))
        .cached(10, 24, TimeUnit.HOURS)
        .rateLimited(10, 1, TimeUnit.MINUTES)
        .build()

    install(Authentication) {
        jwt("jwt-auth0") {
            verifier(jwkProvider, System.getenv("AUTH0_CLIENT_DOMAIN"))
            validate { credential -> validateCreds(credential) }
        }


        oauth("oauth-auth0") {
            urlProvider = { "http://localhost:8080/hello" }
            providerLookup = {
                OAuthServerSettings.OAuth2ServerSettings(
                    name = "oauth",
                    authorizeUrl = " https://${System.getenv("AUTH0_CLIENT_DOMAIN")}/",
                    accessTokenUrl = "https://${System.getenv("AUTH0_CLIENT_DOMAIN")}/token",
                    requestMethod = HttpMethod.Post,
                    clientId = System.getenv("AUTH0_CLIENT_ID"),
                    clientSecret = System.getenv("AUTH0_CLIENT_SECRET"),
                    defaultScopes = listOf("https://www.googleapis.com/auth/userinfo.profile")
                )
            }
            client = httpClient
        }
    }

    routing {
        get("/login") {
            // Redirects to 'authorizeUrl' automatically
        }

        authenticate("oauth-auth0") {
            get("/hello") {
                val principal = call.principal<JWTPrincipal>()

                if (principal == null) {
                    call.respond(":-(")
                    return@get
                }
                principal.payload.getClaim("name").let { name ->
                    call.respond("You've successfully logged-in. Hello, $name")
                }

            }
        }
    }
}

fun validateCreds(credential: JWTCredential): JWTPrincipal? {
    val containsAudience = credential.payload.audience.contains(System.getenv("AUDIENCE"))

    if (containsAudience) {
        return JWTPrincipal(credential.payload)
    }

    return null
}