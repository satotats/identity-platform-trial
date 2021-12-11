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

private val log = LoggerFactory.getLogger("Auth0")
private val httpClient = HttpClient(CIO) {
    install(JsonFeature) {
        serializer = JacksonSerializer()
    }
}

private object Auth0Environment {
    val domain: String = System.getenv("AUTH0_CLIENT_DOMAIN")
    val clientSecret: String = System.getenv("AUTH0_CLIENT_SECRET")
    val clientId: String = System.getenv("AUTH0_CLIENT_ID")
}

@Suppress("unused")
fun Application.main() {
    install(Authentication) {
        /** see https://auth0.com/docs/authorization/protocols/protocol-oauth2 */
        oauth("oauth-auth0") {
            urlProvider = { "http://localhost:8080/callback" }
            providerLookup = {
                OAuthServerSettings.OAuth2ServerSettings(
                    name = "oauth",
                    authorizeUrl = "https://${Auth0Environment.domain}/authorize",
                    accessTokenUrl = "https://${Auth0Environment.domain}/oauth/token",
                    requestMethod = HttpMethod.Post,
                    clientId = Auth0Environment.clientId,
                    clientSecret = Auth0Environment.clientSecret,
                    /** explicitly declare the permissions */
                    defaultScopes = listOf("openid", "profile", "email")
                )
            }
            client = httpClient
        }

        /** このサンプルではjwt featureは未利用。
         * もし、ログインの結果取得できたtokenを、クライアントがHTTP Headerに詰めてくれるなら、
         * jwtでの認証も可能…かも(未検証)。 */
        jwt("jwt-auth0") {
            val jwkProvider = JwkProviderBuilder(Auth0Environment.domain)
                .cached(10, 24, TimeUnit.HOURS)
                .rateLimited(10, 1, TimeUnit.MINUTES)
                .build()

            verifier(jwkProvider, Auth0Environment.domain)
            validate { credential -> validateCreds(credential) }
        }
    }

    install(Sessions) {
        cookie<UserSession>("user_session")
    }

    routing { auth0() }
}

private fun Route.auth0() {
    authenticate("oauth-auth0") {
        get("/login") {
            // Redirects to 'authorizeUrl' automatically
        }

        get("/callback") {
            val principal: OAuthAccessTokenResponse.OAuth2? = call.principal()
            log.info(principal?.toString())
            call.sessions.set(UserSession(principal?.accessToken.toString()))
            call.respondRedirect("/hello")
        }

    }

    get("hello") {
        val userSession: UserSession? = call.sessions.get<UserSession>()
        if (userSession != null) {
            val userInfo: String = httpClient.get("https://${Auth0Environment.domain}/userinfo") {
                headers {
                    append(HttpHeaders.Authorization, "Bearer ${userSession.token}")
                }
            }
            call.respond(userInfo)
        } else {
            call.respondRedirect("/")
        }
    }
}


data class UserSession(val token: String)
data class UserInfo(val name: String?)

/** jwtの利用時はここでバリデーションする */
private fun validateCreds(credential: JWTCredential): JWTPrincipal? {
    val containsAudience = credential.payload.audience.contains(System.getenv("AUDIENCE"))

    if (containsAudience) {
        return JWTPrincipal(credential.payload)
    }

    return null
}