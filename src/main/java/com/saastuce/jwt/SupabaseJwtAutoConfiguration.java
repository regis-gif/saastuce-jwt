package com.saastuce.jwt;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.web.client.RestClient;

/**
 * Déclare {@link SupabaseJwtService} dès que la bibliothèque est sur le classpath.
 *
 * <p>Le {@link RestClient.Builder} de l'application est repris s'il existe (Spring Boot 4 le fournit
 * via {@code spring-boot-starter-restclient}), pour que le JWKS passe par la même configuration
 * HTTP que le reste ; à défaut, un builder nu suffit à un simple GET.
 */
@AutoConfiguration
@EnableConfigurationProperties(SupabaseJwtProperties.class)
public class SupabaseJwtAutoConfiguration {

    /** Instanciée par Spring Boot. */
    public SupabaseJwtAutoConfiguration() {}

    @Bean
    @ConditionalOnMissingBean
    SupabaseJwtService supabaseJwtService(
            SupabaseJwtProperties properties, ObjectProvider<RestClient.Builder> restClientBuilder) {
        return new SupabaseJwtService(
                properties.jwtSecret(),
                properties.jwksUri(),
                properties.clientId(),
                restClientBuilder.getIfAvailable(RestClient::builder));
    }
}
