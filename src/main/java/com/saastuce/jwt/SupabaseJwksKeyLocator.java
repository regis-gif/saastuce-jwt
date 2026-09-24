package com.saastuce.jwt;

import java.security.Key;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import io.jsonwebtoken.Header;
import io.jsonwebtoken.Locator;
import io.jsonwebtoken.ProtectedHeader;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.Jwks;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.client.RestClient;

/**
 * Résout la clé publique d'un jeton Supabase à partir du JWKS du projet.
 *
 * <p>Supabase ne signe plus les jetons utilisateur avec le secret partagé HS256 : depuis la
 * migration vers les JWT Signing Keys, ils sont signés en ES256 et seule la clé publique publiée
 * sur {@code /auth/v1/.well-known/jwks.json} permet de les vérifier. Le secret hérité ne sert plus
 * qu'à valider les clés d'API anon et service_role.
 *
 * <p>Les clés tournent, donc rien n'est mis en cache définitivement : un {@code kid} inconnu
 * déclenche un rechargement. Ce rechargement est limité en fréquence, sinon des jetons forgés avec
 * des {@code kid} aléatoires suffiraient à faire marteler Supabase par l'API.
 */
public class SupabaseJwksKeyLocator implements Locator<Key> {

    private static final Logger log = LoggerFactory.getLogger(SupabaseJwksKeyLocator.class);
    private static final Duration REFRESH_COOLDOWN = Duration.ofMinutes(1);

    private final RestClient restClient;
    private final String jwksUri;

    private volatile Map<String, Key> keysByKid = Map.of();
    private volatile long lastFetchNanos;
    private volatile boolean everFetched;

    /**
     * Ne contacte pas encore Supabase : le JWKS est chargé au premier jeton à vérifier.
     *
     * @param restClient le client HTTP qui récupère le JWKS
     * @param jwksUri l'adresse du JWKS du projet Supabase
     */
    public SupabaseJwksKeyLocator(RestClient restClient, String jwksUri) {
        this.restClient = restClient;
        this.jwksUri = jwksUri;
    }

    @Override
    public Key locate(Header header) {
        if (!(header instanceof ProtectedHeader protectedHeader)) {
            return null;
        }
        // Un jeton HS256 n'a rien à faire ici. jjwt refuserait déjà de vérifier un MAC avec une clé
        // publique EC, mais rendre le refus explicite évite qu'une évolution de la bibliothèque
        // rouvre la confusion d'algorithme, où la clé publique — qui est publique — servirait de
        // secret HMAC.
        String algorithm = protectedHeader.getAlgorithm();
        if (algorithm == null || algorithm.startsWith("HS")) {
            return null;
        }

        String kid = protectedHeader.getKeyId();
        if (kid == null) {
            return null;
        }

        Key key = keysByKid.get(kid);
        if (key != null) {
            return key;
        }
        if (refreshAllowed()) {
            refresh();
        }
        return keysByKid.get(kid);
    }

    private boolean refreshAllowed() {
        return !everFetched
                || System.nanoTime() - lastFetchNanos >= REFRESH_COOLDOWN.toNanos();
    }

    private synchronized void refresh() {
        if (everFetched && !refreshAllowed()) {
            return;
        }
        lastFetchNanos = System.nanoTime();
        everFetched = true;
        try {
            String body = restClient.get().uri(jwksUri).retrieve().body(String.class);
            if (body == null || body.isBlank()) {
                log.warn("Empty JWKS response from {}", jwksUri);
                return;
            }
            Map<String, Key> keys = new HashMap<>();
            for (Jwk<?> jwk : Jwks.setParser().build().parse(body).getKeys()) {
                if (jwk.getId() != null) {
                    keys.put(jwk.getId(), jwk.toKey());
                }
            }
            keysByKid = Map.copyOf(keys);
            log.info("Loaded {} Supabase signing key(s) from {}", keys.size(), jwksUri);
        } catch (Exception e) {
            // On garde les clés déjà connues : une panne réseau ne doit pas déconnecter tout le
            // monde alors que la clé en cours de rotation est encore en cache.
            log.warn("Could not refresh the Supabase JWKS from {}: {}", jwksUri, e.toString());
        }
    }
}
