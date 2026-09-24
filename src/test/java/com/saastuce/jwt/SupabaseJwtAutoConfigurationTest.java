package com.saastuce.jwt;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

/**
 * Ce que voit une application qui ajoute la bibliothèque : le service est là sans rien déclarer,
 * configuré par {@code saastuce.supabase.*}, et désactivé tant que rien n'est renseigné.
 */
class SupabaseJwtAutoConfigurationTest {

    private final ApplicationContextRunner contexte = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(SupabaseJwtAutoConfiguration.class));

    @Test
    void declaresAnUnconfiguredServiceWhenNothingIsSet() {
        contexte.run(application -> {
            assertThat(application).hasSingleBean(SupabaseJwtService.class);
            assertThat(application.getBean(SupabaseJwtService.class).isConfigured()).isFalse();
        });
    }

    @Test
    void readsItsConfigurationUnderSaastuceSupabase() {
        contexte.withPropertyValues(
                        "saastuce.supabase.jwt-secret=test-secret-with-at-least-32-characters!")
                .run(application ->
                        assertThat(application.getBean(SupabaseJwtService.class).isConfigured())
                                .isTrue());
    }

    @Test
    void stepsAsideForAServiceTheApplicationDeclares() {
        SupabaseJwtService propre = new SupabaseJwtService(
                "", "", "", org.springframework.web.client.RestClient.builder());
        contexte.withBean(SupabaseJwtService.class, () -> propre)
                .run(application ->
                        assertThat(application.getBean(SupabaseJwtService.class)).isSameAs(propre));
    }
}
