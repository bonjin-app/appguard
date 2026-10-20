package io.appguard;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import static org.assertj.core.api.Assertions.*;

class AutoConfigurationTest {
    WebApplicationContextRunner context=new WebApplicationContextRunner().withConfiguration(AutoConfigurations.of(AppGuardAutoConfiguration.class));
    @Test void disabledByDefaultDoesNotInstallFilter(){context.run(c->assertThat(c).doesNotHaveBean(AppGuardFilter.class));}
    @Test void enabledWithoutSecurityDependenciesOrOriginOrAppFailsStartup(){
        context.withPropertyValues("appguard.enabled=true").run(c->assertThat(c).hasFailed());
        context.withPropertyValues("appguard.enabled=true","appguard.app-id=test-app","appguard.origin=https://api.example.test").run(c->assertThat(c).hasFailed());
        context.withPropertyValues("appguard.enabled=true","appguard.app-id=test-app").withBean(IdentityResolver.class,()->(r,p)->null).withBean(ReplayStore.class,LocalReplayStore::new).run(c->assertThat(c).hasFailed());
    }
    @Test void defaultTransportRejectsForwardedHeaderInterpretationAtStartup(){
        context.withPropertyValues("appguard.enabled=true","appguard.app-id=test-app","appguard.origin=https://api.example.test","server.forward-headers-strategy=native")
            .withBean(IdentityResolver.class,()->(r,p)->null).withBean(ReplayStore.class,LocalReplayStore::new)
            .run(c->assertThat(c).hasFailed());
    }
    @Test void missingReplayAndMissingAppIdFailStartupWithOtherDependenciesPresent(){
        context.withPropertyValues("appguard.enabled=true","appguard.app-id=test-app","appguard.origin=https://api.example.test").withBean(IdentityResolver.class,()->(r,p)->null).run(c->assertThat(c).hasFailed());
        context.withPropertyValues("appguard.enabled=true","appguard.origin=https://api.example.test").withBean(IdentityResolver.class,()->(r,p)->null).withBean(ReplayStore.class,LocalReplayStore::new).run(c->assertThat(c).hasFailed());
    }
    @Test void explicitDependenciesRegisterAfterSpringSecurityForAllDispatches(){
        context.withPropertyValues("appguard.enabled=true","appguard.app-id=test-app","appguard.origin=https://api.example.test").withBean(IdentityResolver.class,()->(r,p)->null).withBean(ReplayStore.class,LocalReplayStore::new).run(c->{
            assertThat(c).hasNotFailed().hasSingleBean(AppGuardFilter.class);
            FilterRegistrationBean<?> registration=c.getBean("appGuardFilterRegistration",FilterRegistrationBean.class);
            assertThat(registration.getOrder()).isEqualTo(-90);
        });
    }
}
