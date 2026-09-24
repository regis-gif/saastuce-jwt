package com.saastuce.jwt;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * La configuration de la vérification des jetons Supabase, sous {@code saastuce.supabase}.
 *
 * <p>Chaque application la relie à ses variables d'environnement dans son {@code application.yml}
 * ({@code jwks-uri: ${SUPABASE_JWKS_URI:}}…). Tout vide, la vérification est désactivée : c'est
 * le cas en développement local sans Supabase.
 *
 * @param jwksUri le JWKS du projet, {@code https://<ref>.supabase.co/auth/v1/.well-known/jwks.json}
 * @param jwtSecret le secret HS256 hérité — tests uniquement, ignoré dès que {@code jwksUri} est posé
 * @param clientId le client OAuth de ce produit ; vide, le claim {@code client_id} n'est pas vérifié
 */
@ConfigurationProperties("saastuce.supabase")
public record SupabaseJwtProperties(String jwksUri, String jwtSecret, String clientId) {

    /** Une propriété absente vaut chaîne vide, comme une variable d'environnement non posée. */
    public SupabaseJwtProperties {
        jwksUri = jwksUri == null ? "" : jwksUri;
        jwtSecret = jwtSecret == null ? "" : jwtSecret;
        clientId = clientId == null ? "" : clientId;
    }
}
