package com.saastuce.jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.Jwks;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.ExpectedCount;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

/**
 * Le mode JWKS est ce qui rend l'authentification Supabase utilisable : depuis la migration vers
 * les JWT Signing Keys, un projet récent signe les jetons utilisateur en ES256 et le secret partagé
 * hérité ne peut plus rien vérifier. Rien ici ne contacte Supabase — le JWKS est servi par un
 * serveur simulé, à partir d'une paire de clés fabriquée pour le test.
 */
class SupabaseJwtServiceTest {

    private static final String JWKS_URI = "https://project.supabase.co/auth/v1/.well-known/jwks.json";
    private static final String ISSUER = "https://project.supabase.co/auth/v1";
    private static final String KID = "test-signing-key";

    private final KeyPair signingKeys = Jwts.SIG.ES256.keyPair().build();

    @Test
    void acceptsATokenSignedByAKeyPublishedInTheJwks() {
        SupabaseJwtService service = jwksService(jwksJson(signingKeys, KID));

        UUID userId = UUID.randomUUID();
        Optional<SupabaseJwtService.SupabaseUserClaims> claims =
                service.parseToken(es256Token(userId, "Artisan@Example.test"));

        assertThat(claims).isPresent();
        assertThat(claims.get().userId()).isEqualTo(userId);
        assertThat(claims.get().email()).isEqualTo("artisan@example.test");
    }

    /** Une clé retirée du JWKS — révoquée, ou jamais émise par ce projet — ne vaut plus rien. */
    @Test
    void rejectsATokenSignedByAKeyAbsentFromTheJwks() {
        KeyPair otherKeys = Jwts.SIG.ES256.keyPair().build();
        SupabaseJwtService service = jwksService(jwksJson(otherKeys, "some-other-kid"));

        assertThat(service.parseToken(es256Token(UUID.randomUUID(), "a@b.test"))).isEmpty();
    }

    /**
     * Garde-fou contre la confusion d'algorithme : la clé publique du JWKS est publique, donc si
     * elle pouvait servir de secret HMAC, n'importe qui forgerait un jeton HS256 valide.
     */
    @Test
    void rejectsAnHs256TokenWhenTheJwksModeIsActive() {
        SupabaseJwtService service = jwksService(jwksJson(signingKeys, KID));

        String forged =
                Jwts.builder()
                        .header()
                        .keyId(KID)
                        .and()
                        .subject(UUID.randomUUID().toString())
                        .expiration(Date.from(Instant.now().plusSeconds(300)))
                        .signWith(
                                Keys.hmacShaKeyFor(
                                        "a-secret-long-enough-for-hmac-sha256-here"
                                                .getBytes(StandardCharsets.UTF_8)))
                        .compact();

        assertThat(service.parseToken(forged)).isEmpty();
    }

    /**
     * Un JWKS tel que Supabase le sert réellement, relevé le 18/07/2026. Il porte des membres que
     * la RFC 7517 autorise sans que jjwt en ait besoin — {@code ext}, {@code key_ops}, {@code use}
     * — et c'est exactement le genre de détail qui fait échouer un parseur en production alors que
     * les clés fabriquées pour les tests passent. Seule la partie publique figure ici.
     */
    @Test
    void parsesAJwksAsSupabaseActuallyServesIt() {
        String realJwks =
                """
                {"keys":[{"alg":"ES256","crv":"P-256","ext":true,"key_ops":["verify"],\
                "kid":"36234655-3202-4ce6-bc5d-ae6f5852bccc","kty":"EC","use":"sig",\
                "x":"ehn0PaHnyUEQo4dJw7t5cVLmIyZw3_v8X50Qs8JYUNI",\
                "y":"3MATzXjTuVLtReXAZo7Ked3bmEr0kbzivoxVrAFrusQ"}]}""";

        Set<Jwk<?>> keys = Jwks.setParser().build().parse(realJwks).getKeys();

        assertThat(keys).singleElement();
        assertThat(keys.iterator().next().getId())
                .isEqualTo("36234655-3202-4ce6-bc5d-ae6f5852bccc");
    }

    /** Sans secret ni JWKS, le service se tait : c'est ce qui désactive l'auth Supabase en local. */
    @Test
    void isNotConfiguredWithoutASecretOrAJwks() {
        SupabaseJwtService service = new SupabaseJwtService("", "", "", RestClient.builder());

        assertThat(service.isConfigured()).isFalse();
        assertThat(service.parseToken(es256Token(UUID.randomUUID(), "a@b.test"))).isEmpty();
    }

    /**
     * L'émetteur attendu se déduit de {@code saastuce.supabase.jwks-uri} lui-même — un jeton signé
     * par un autre projet Supabase, donc portant un {@code iss} différent, est rejeté sans qu'aucune
     * variable dédiée n'ait été posée.
     */
    @Test
    void rejectsATokenFromAnUnexpectedIssuer() {
        SupabaseJwtService service = jwksService(jwksJson(signingKeys, KID));

        String token =
                es256TokenBuilder(UUID.randomUUID(), "a@b.test")
                        .issuer("https://another-project.supabase.co/auth/v1")
                        .signWith(signingKeys.getPrivate(), Jwts.SIG.ES256)
                        .compact();

        assertThat(service.parseToken(token)).isEmpty();
    }

    /**
     * Le cœur de #224 : un jeton signé par le même projet, avec la même clé, mais délivré à un
     * autre client OAuth du groupe (un autre produit Saastuce).
     */
    @Test
    void rejectsATokenIssuedToAnotherOAuthClient() {
        SupabaseJwtService service =
                jwksService(jwksJson(signingKeys, KID), "marcel-chantier-client-id");

        String token =
                es256TokenBuilder(UUID.randomUUID(), "a@b.test")
                        .claim("client_id", "marcel-abonnement-client-id")
                        .signWith(signingKeys.getPrivate(), Jwts.SIG.ES256)
                        .compact();

        assertThat(service.parseToken(token)).isEmpty();
    }

    /** Le client attendu, une fois renseigné, est accepté. */
    @Test
    void acceptsATokenIssuedToTheExpectedOAuthClient() {
        SupabaseJwtService service =
                jwksService(jwksJson(signingKeys, KID), "marcel-chantier-client-id");

        String token =
                es256TokenBuilder(UUID.randomUUID(), "a@b.test")
                        .claim("client_id", "marcel-chantier-client-id")
                        .signWith(signingKeys.getPrivate(), Jwts.SIG.ES256)
                        .compact();

        assertThat(service.parseToken(token)).isPresent();
    }

    /**
     * Un jeton sans claim {@code client_id} du tout — le cas des liens "Connect as admin" générés
     * côté serveur par {@code /admin/generate_link}, hors flux OAuth — reste accepté : seule une
     * valeur présente et différente de la nôtre est un refus.
     */
    @Test
    void acceptsATokenWithoutAClientIdClaimWhenAClientIdIsExpected() {
        SupabaseJwtService service =
                jwksService(jwksJson(signingKeys, KID), "marcel-chantier-client-id");

        assertThat(service.parseToken(es256Token(UUID.randomUUID(), "a@b.test"))).isPresent();
    }

    private SupabaseJwtService jwksService(String jwksBody) {
        return jwksService(jwksBody, "");
    }

    private SupabaseJwtService jwksService(String jwksBody, String clientId) {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer.bindTo(builder)
                .ignoreExpectOrder(true)
                .build()
                .expect(ExpectedCount.manyTimes(), requestTo(JWKS_URI))
                .andRespond(withSuccess(jwksBody, MediaType.APPLICATION_JSON));
        return new SupabaseJwtService("", JWKS_URI, clientId, builder);
    }

    private String es256Token(UUID subject, String email) {
        return es256TokenBuilder(subject, email)
                .signWith(signingKeys.getPrivate(), Jwts.SIG.ES256)
                .compact();
    }

    /** Émetteur déjà posé sur {@link #ISSUER} : c'est celui que porte tout jeton Supabase réel. */
    private JwtBuilder es256TokenBuilder(UUID subject, String email) {
        return Jwts.builder()
                .header()
                .keyId(KID)
                .and()
                .issuer(ISSUER)
                .subject(subject.toString())
                .claim("email", email)
                .expiration(Date.from(Instant.now().plusSeconds(300)));
    }

    /**
     * Sérialise le JWK à la main : toString() d'un Jwk rend un toString de Map, pas du JSON. Les
     * membres d'une clé publique EC sont tous des chaînes, donc l'échappement ne se pose pas.
     */
    private String jwksJson(KeyPair keyPair, String kid) {
        Jwk<?> jwk = Jwks.builder().key(keyPair.getPublic()).id(kid).build();
        String members =
                jwk.entrySet().stream()
                        .map(e -> "\"" + e.getKey() + "\":\"" + e.getValue() + "\"")
                        .collect(Collectors.joining(","));
        return "{\"keys\":[{" + members + "}]}";
    }
}
