package io.appguard.example;

import io.appguard.*;
import io.lettuce.core.ClientOptions;
import io.lettuce.core.SocketOptions;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.Duration;
import java.util.*;
import org.springframework.boot.*;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.MapPropertySource;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.*;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;

/** Dedicated loopback mTLS backend. A trusted gateway must finish bounded upload capture first. */
@SpringBootConfiguration
@EnableAutoConfiguration
public class BackendMain {
    public static void main(String[] args){
        try{
            if(args.length!=0)throw new IllegalArgumentException("Command-line properties are not supported");
            BackendSettings settings=new BackendSettings(System.getenv());BackendCounters counters=new BackendCounters(settings.counterFile);
            SpringApplication app=new SpringApplication(BackendMain.class);app.setAddCommandLineProperties(false);
            app.addInitializers(context->{
                context.getEnvironment().getPropertySources().addFirst(new MapPropertySource("appguardFixedBackend",settings.properties()));
                context.getBeanFactory().registerSingleton("backendSettings",settings);context.getBeanFactory().registerSingleton("backendCounters",counters);
            });
            app.run();System.out.println("APPGUARD_BACKEND_READY");
        }catch(Exception e){System.err.println("APPGUARD_BACKEND_START_FAILED");System.exit(1);}
    }
    @Bean LettuceConnectionFactory redisConnection(BackendSettings settings){
        RedisStandaloneConfiguration config=new RedisStandaloneConfiguration("127.0.0.1",settings.redisPort);config.setDatabase(settings.redisDatabase);
        var client=LettuceClientConfiguration.builder().commandTimeout(Duration.ofSeconds(1)).shutdownTimeout(Duration.ofMillis(100))
            .clientOptions(ClientOptions.builder().autoReconnect(false).socketOptions(SocketOptions.builder().connectTimeout(Duration.ofSeconds(1)).build()).build()).build();
        return new LettuceConnectionFactory(config,client);
    }
    @Bean StringRedisTemplate redisTemplate(LettuceConnectionFactory factory){return new StringRedisTemplate(factory);}
    @Bean ReplayStore replay(StringRedisTemplate redis,BackendCounters counters){
        RedisReplayStore replay=new RedisReplayStore(redis);
        return (scope,expires,now)->{counters.increment("replay");return replay.claim(scope,expires,now);};
    }
    @Bean IdentityResolver identities(BackendSettings settings,BackendCounters counters){
        return IdentityResolver.fromPrincipal((subject,keyId)->{
            counters.increment("key");return settings.subject.equals(subject)&&settings.keyId.equals(keyId)?new KeyRecord(settings.appId,settings.keyId,settings.subject,settings.publicKey,Canonical.ALGORITHM,false):null;
        });
    }
    @Bean FilterRegistrationBean<Filter> dispatchCounter(BackendCounters counters){
        FilterRegistrationBean<Filter> registration=new FilterRegistrationBean<>((request,response,chain)->{counters.increment("dispatch");chain.doFilter(request,response);});
        registration.setOrder(-110);registration.setDispatcherTypes(DispatcherType.REQUEST);return registration;
    }
    static boolean validBearer(String value,byte[] expected){
        if(value==null || value.length()>8192 || !value.matches("(?i:Bearer) [A-Za-z0-9._~+/-]{32,}=*"))return false;
        try{return MessageDigest.isEqual(expected,MessageDigest.getInstance("SHA-256").digest(value.substring(7).getBytes(StandardCharsets.US_ASCII)));}
        catch(NoSuchAlgorithmException e){throw new IllegalStateException("SHA-256 unavailable");}
    }
    @Bean SecurityFilterChain security(HttpSecurity http,BackendSettings settings,BackendCounters counters)throws Exception {
        return http.csrf(c->c.disable()).requestCache(c->c.disable()).sessionManagement(s->s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(a->a.anyRequest().permitAll())
            .addFilterBefore((request,response,chain)->{
                counters.increment("auth");HttpServletRequest req=(HttpServletRequest)request;
                List<String> fields=Collections.list(req.getHeaders("Authorization"));
                if(fields.size()==1 && validBearer(fields.get(0),settings.bearerHash))SecurityContextHolder.getContext().setAuthentication(UsernamePasswordAuthenticationToken.authenticated(settings.subject,null,List.of()));
                chain.doFilter(request,response);
            },AnonymousAuthenticationFilter.class).build();
    }
    @Bean ServletRegistrationBean<HttpServlet> resource(BackendSettings settings,BackendCounters counters){
        return new ServletRegistrationBean<>(new HttpServlet(){
            @Override protected void service(HttpServletRequest request,HttpServletResponse response)throws IOException {
                if(!"POST".equals(request.getMethod()) || !"/v1/items".equals(request.getRequestURI()) || request.getUserPrincipal()==null || !settings.subject.equals(request.getUserPrincipal().getName()) || !(request.getAttribute(AppGuardFilter.VERIFICATION_ATTRIBUTE) instanceof VerificationResult)){
                    response.setStatus(403);response.setContentType("application/json");response.getOutputStream().write("{\"code\":\"RESOURCE_FORBIDDEN\"}".getBytes(StandardCharsets.US_ASCII));return;
                }
                counters.increment("resource");byte[] body=request.getInputStream().readAllBytes();response.setStatus(200);response.setContentType("application/octet-stream");response.setContentLength(body.length);response.getOutputStream().write(body);
            }
        },"/*");
    }
}
