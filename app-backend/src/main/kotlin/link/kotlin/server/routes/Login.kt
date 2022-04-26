package link.kotlin.server.routes

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import io.ktor.application.call
import io.ktor.request.receive
import io.ktor.response.respond
import io.ktor.routing.Routing
import io.ktor.routing.post
import kotlinx.serialization.Serializable
import link.kotlin.server.ApplicationFactory
import link.kotlin.server.plugins.AuthenticationException
import java.util.Date


context(ApplicationFactory)
fun Routing.login() {
    post("/login") {
        val request = call.receive<LoginBody>()
        val db = kotlinerDao.get(request.email)

        db ?: throw AuthenticationException()

        val result = bcryptVerifier.verify(
            request.password,
            db.password
        )

        if (result.verified) {
            val token = JWT.create()
                .withAudience(jwtConfig.audience)
                .withIssuer(jwtConfig.issuer)
                .withClaim("id", db.id)
                .withIssuedAt(Date(System.currentTimeMillis()))
                .sign(Algorithm.HMAC512(jwtConfig.secret))

            call.respond(hashMapOf("token" to token))
        } else {
            throw AuthenticationException()
        }
    }
}

@Serializable
data class LoginBody(
    val email: String,
    val password: CharArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as LoginBody

        if (email != other.email) return false
        if (!password.contentEquals(other.password)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = email.hashCode()
        result = 31 * result + password.contentHashCode()
        return result
    }
}
