# saastuce-jwt

Vérification des jetons **Supabase Auth** commune aux backends Saastuce
(`marcel-chantier-backend`, `saastuce-billing-backend`), pour ne plus dupliquer ce code.

- JWKS (ES256) avec cache et rechargement limité en fréquence ; HS256 hérité pour les tests.
- Émetteur attendu déduit du `jwks-uri` ; claim `client_id` vérifié quand `client-id` est posé
  (un jeton délivré à un autre produit du groupe est refusé).
- Auto-configuration Spring Boot : ajouter la dépendance suffit à obtenir un bean `SupabaseJwtService`.

## Utilisation

```groovy
repositories {
    mavenCentral()
    maven { url 'https://jitpack.io' }
}

dependencies {
    implementation 'com.github.regis-gif:saastuce-jwt:v1.0.0'
}
```

```yaml
saastuce:
  supabase:
    jwks-uri: ${SUPABASE_JWKS_URI:}
    jwt-secret: ${SUPABASE_JWT_SECRET:}          # tests uniquement, ignoré si jwks-uri est posé
    client-id: ${SUPABASE_OAUTH_CLIENT_ID:}
```

```java
supabaseJwtService.parseToken(token)   // Optional<SupabaseUserClaims(userId, email)>
```

Le filtre HTTP reste propre à chaque application.

## Publier une version

JitPack construit la bibliothèque à partir d'un tag Git (`jitpack.yml`) :

```sh
git tag v1.1.0 && git push origin v1.1.0
```

La CI (`check`, puis `publication` sur un tag) fait construire la version par JitPack et échoue
si la construction échoue. Renovate propose ensuite la montée de version dans les backends — et tient
à jour les dépendances de la bibliothèque elle-même (Spring Boot, jjwt), avec fusion automatique des
mises à jour mineures et correctives quand la CI passe.

## Développement

```sh
./gradlew build          # compile (Java 21), Checkstyle, tests
```
