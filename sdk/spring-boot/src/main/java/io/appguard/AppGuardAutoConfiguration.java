package io.appguard;
import jakarta.servlet.DispatcherType;
import java.time.Clock;
import java.util.EnumSet;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.*;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
/** Opt-in only. Missing security beans fail startup; there are no permissive defaults. */
@AutoConfiguration
@ConditionalOnWebApplication(type=ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(prefix="appguard",name="enabled",havingValue="true")
@EnableConfigurationProperties(AppGuardProperties.class)
public class AppGuardAutoConfiguration {
    @Bean public AppGuardFilter appGuardFilter(AppGuardProperties properties,IdentityResolver identities,ReplayStore replay,ObjectProvider<Clock> clock,org.springframework.core.env.Environment env){
        String forwarding=env.getProperty("server.forward-headers-strategy","none");
        if(!properties.isAllowInsecureTransport() && !forwarding.equalsIgnoreCase("none")) throw new IllegalStateException("Forwarded transport interpretation requires an explicit AppGuard transport-boundary opt-in");
        return new AppGuardFilter(properties.getAppId(),properties.getOrigin(),identities,replay,clock.getIfAvailable(Clock::systemUTC),properties.isAllowInsecureTransport());
    }
    @Bean public FilterRegistrationBean<AppGuardFilter> appGuardFilterRegistration(AppGuardFilter filter,org.springframework.core.env.Environment env){
        FilterRegistrationBean<AppGuardFilter> registration=new FilterRegistrationBean<>(filter);
        registration.setName("appguard");registration.setOrder(-90);registration.setDispatcherTypes(EnumSet.allOf(DispatcherType.class));registration.setAsyncSupported(true);
        registration.setEnabled(env.getProperty("appguard.register-servlet-filter",Boolean.class,true));return registration;
    }
}
