package com.saastuce.jwt;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Optional;
import java.util.UUID;
import javax.crypto.SecretKey;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParserBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Locator;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.client.RestClient;

/**
 * Vérifie les jetons émis par Supabase Auth, l'IdP commun aux produits Saastuce.
 *
 * <p>Deux modes, exclusifs l'un de l'autre. Le mode JWKS ({@code saastuce.supabase.jwks-uri})
 * vérifie les signatures asymétriques ES256 contre les clés publiques du projet : c'est le seul qui
 * fonctionne avec un projet Supabase récent, où les jetons utilisateur sont signés par les JWT
 * Signing Keys. Le mode secret partagé ({@code saastuce.supabase.jwt-secret}) vérifie du HS256 ; il
 * ne subsiste que pour les tests, qui forgent leurs propres jetons sans contacter Supabase.
 *
 * <p>Si les deux sont renseignés, le JWKS gagne : accepter aussi le HS256 laisserait un second
 * chemin de vérification, dont le secret traîne en clair dans les variables d'environnement, alors
 * que plus aucun jeton légitime ne l'emprunte.
 *
 * <p>La signature ne suffit pas : Supabase Auth sert de serveur OAuth 2.1 à tout le groupe, et un
 * jeton émis pour un autre produit ({@code client_id} distinct) est signé par le même projet, avec
 * la même clé (marcel-chantier-backend#224). L'émetteur attendu n'est pas une variable séparée : il
 * se déduit de {@code jwks-uri} lui-même (on retire le suffixe {@code /.well-known/jwks.json}) —
 * dupliquer l'URL du projet dans une seconde variable reproduirait le piège qui a cassé "Connect as
 * admin" en silence le jour où deux URL Supabase ont divergé. {@code saastuce.supabase.client-id}
 * vérifie en plus que le jeton a été délivré à ce produit-ci.
 *
 * <p>Le destinataire d'un jeton d'accès Supabase OAuth n'est pas porté par {@code aud}, qui vaut
 * toujours la constante {@code "authenticated"} quel que soit le client : c'est le claim racine
 * {@code client_id}. Il n'existe que sur les jetons obtenus via le flux OAuth ; un jeton sans ce
 * claim (lien "Connect as admin" généré par {@code /admin/generate_link}) reste accepté — seule une
 * valeur présente et différente de la nôtre est un refus.
 */
public class SupabaseJwtService {

    private static final Logger log = LoggerFactory.getLogger(SupabaseJwtService.class);
    private static final String JWKS_SUFFIX = "/.well-known/jwks.json";

    private final Locator<Key> keyLocator;
    private final SecretKey secretKey;
    private final String issuer;
    private final String clientId;

    /**
     * Choisit le mode de vérification : JWKS s'il est posé, sinon secret HS256, sinon aucun.
     *
     * @param secret le secret HS256 hérité, ignoré si {@code jwksUri} est posé
     * @param jwksUri le JWKS du projet ; en déduit aussi l'émetteur attendu
     * @param clientId le client OAuth de ce produit, vide pour ne pas le vérifier
     * @param restClientBuilder de quoi récupérer le JWKS
     */
    public SupabaseJwtService(
            String secret,
            String jwksUri,
            String clientId,
            RestClient.Builder restClientBuilder) {
        this.clientId = clientId;
        if (!jwksUri.isBlank()) {
            this.keyLocator = new SupabaseJwksKeyLocator(restClientBuilder.build(), jwksUri);
            this.secretKey = null;
            this.issuer =
                    jwksUri.endsWith(JWKS_SUFFIX)
                            ? jwksUri.substring(0, jwksUri.length() - JWKS_SUFFIX.length())
                            : "";
            if (!secret.isBlank()) {
                log.warn(
                        "saastuce.supabase.jwt-secret is ignored: the JWKS at {} takes precedence",
                        jwksUri);
            }
        } else if (!secret.isBlank()) {
            this.keyLocator = null;
            this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
            this.issuer = "";
        } else {
            this.keyLocator = null;
            this.secretKey = null;
            this.issuer = "";
        }
    }

    /**
     * Dit si une vérification est possible.
     *
     * @return faux sans JWKS ni secret : l'authentification Supabase est alors désactivée
     */
    public boolean isConfigured() {
        return keyLocator != null || secretKey != null;
    }

    /**
     * Vérifie un jeton et en extrait l'utilisateur.
     *
     * @param token le jeton, sans le préfixe {@code Bearer}
     * @return l'utilisateur, ou vide pour tout jeton invalide, expiré, d'un autre émetteur ou d'un
     *     autre client OAuth — jamais d'exception, le filtre n'a qu'à répondre 401
     */
    public Optional<SupabaseUserClaims> parseToken(String token) {
        if (!isConfigured()) {
            return Optional.empty();
        }
        try {
            JwtParserBuilder parser = Jwts.parser();
            if (keyLocator != null) {
                parser.keyLocator(keyLocator);
            } else {
                parser.verifyWith(secretKey);
            }
            if (!issuer.isBlank()) {
                parser.requireIssuer(issuer);
            }
            Claims claims = parser.build().parseSignedClaims(token).getPayload();
            String tokenClientId = claims.get("client_id", String.class);
            if (!clientId.isBlank() && tokenClientId != null && !tokenClientId.equals(clientId)) {
                log.debug("Rejecting a Supabase token issued to another client: {}", tokenClientId);
                return Optional.empty();
            }
            UUID userId = UUID.fromString(claims.getSubject());
            String email = claims.get("email", String.class);
            if (email == null || email.isBlank()) {
                email = userId + "@supabase.local";
            }
            return Optional.of(new SupabaseUserClaims(userId, email.toLowerCase()));
        } catch (Exception ignored) {
            return Optional.empty();
        }
    }

    /**
     * L'utilisateur porté par un jeton vérifié.
     *
     * @param userId le {@code sub} du jeton
     * @param email l'adresse en minuscules, ou {@code <sub>@supabase.local} si le jeton n'en porte pas
     */
    public record SupabaseUserClaims(UUID userId, String email) {}
}
