package com.satotats.trial.auth0

import com.auth0.jwk.JwkProviderBuilder
import io.ktor.application.*
import io.ktor.auth.*
import io.ktor.auth.jwt.*
import io.ktor.client.*
import io.ktor.client.engine.cio.*
import io.ktor.client.features.json.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.response.*
import io.ktor.routing.*
import io.ktor.sessions.*
import org.slf4j.LoggerFactory
import java.util.concurrent.TimeUnit

val log = LoggerFactory.getLogger("Auth0")

@Suppress("unused")
fun Application.main() {
    val httpClient = HttpClient(CIO) {
        install(JsonFeature) {
            serializer = JacksonSerializer()
        }
    }

    val jwkProvider = JwkProviderBuilder(System.getenv("AUTH0_CLIENT_DOMAIN"))
        .cached(10, 24, TimeUnit.HOURS)
        .rateLimited(10, 1, TimeUnit.MINUTES)
        .build()

    install(Authentication) {
        // 使ってない
        jwt("jwt-auth0") {
            verifier(jwkProvider, System.getenv("AUTH0_CLIENT_DOMAIN"))
            validate { credential -> validateCreds(credential) }
        }


        oauth("oauth-auth0") {
            urlProvider = { "http://localhost:8080/callback" }
            providerLookup = {
                OAuthServerSettings.OAuth2ServerSettings(
                    name = "oauth",
                    authorizeUrl = "https://${System.getenv("AUTH0_CLIENT_DOMAIN")}/authorize",
                    accessTokenUrl = "https://${System.getenv("AUTH0_CLIENT_DOMAIN")}/oauth/token",
                    requestMethod = HttpMethod.Post,
                    clientId = System.getenv("AUTH0_CLIENT_ID"),
                    clientSecret = System.getenv("AUTH0_CLIENT_SECRET"),
//                    defaultScopes = listOf("https://www.googleapis.com/auth/userinfo.profile")
                )
            }
            client = httpClient
        }
    }

    install(Sessions) {
        cookie<UserSession>("user_session")
    }

    routing {
        authenticate("oauth-auth0") {
            get("/login") {
                // Redirects to 'authorizeUrl' automatically
            }

            get("/callback") {
                val principal: OAuthAccessTokenResponse.OAuth2? = call.principal()
                log.info(principal?.accessToken)
//                call.response.headers.append(HttpHeaders.Authorization, "Bearer ${principal?.accessToken.toString()}")
                call.sessions.set(UserSession(principal?.accessToken.toString()))
                call.respondRedirect("/hello")
            }

        }

        get("hello") {
            val userSession: UserSession? = call.sessions.get<UserSession>()
            if (userSession != null) {
                val userInfo: UserInfo = httpClient.get("https://${System.getenv("AUTH0_CLIENT_DOMAIN")}/userinfo") {
                    headers {
                        append(HttpHeaders.Authorization, "Bearer ${userSession.token}")
                    }
                }
                call.respond(userInfo.toString())
            } else {
                call.respondRedirect("/")
            }
        }

//        authenticate("jwt-auth0") {
//            get("/hello") {
//                val principal = call.principal<JWTPrincipal>()
//                log.info(principal.toString())
//                if (principal == null) {
//                    call.respond(":-(")
//                    return@get
//                }
//                principal.payload.getClaim("name").let { name ->
//                    call.respond("You've successfully logged-in. Hello, $name")
//                }
//            }
//        }
    }
}

fun validateCreds(credential: JWTCredential): JWTPrincipal? {
    val containsAudience = credential.payload.audience.contains(System.getenv("AUDIENCE"))

    if (containsAudience) {
        return JWTPrincipal(credential.payload)
    }

    return null
}

data class UserSession(val token: String)

data class UserInfo(val name: String?)
