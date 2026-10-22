package io.appguard;

import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.apache.catalina.startup.Tomcat;
import org.apache.coyote.http11.AbstractHttp11Protocol;
import org.junit.jupiter.api.*;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import static org.assertj.core.api.Assertions.*;

/** Records a deployment limitation, not an SDK slow-upload protection claim. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ServletBodyDeadlineLimitTest {
    ConfigurableApplicationContext context;
    int port;
    @BeforeAll void start() throws Exception {
        context=new SpringApplicationBuilder(EmbeddedHttpTest.App.class).properties(
            "server.address=127.0.0.1","server.port=0","server.forward-headers-strategy=none",
            "appguard.enabled=true","appguard.app-id=test-app","appguard.origin="+SignedRequests.ORIGIN,
            "appguard.allow-insecure-transport=true","spring.main.banner-mode=off","logging.level.root=ERROR").run();
        port=context.getEnvironment().getRequiredProperty("local.server.port",Integer.class);
        // Test-only reflection preserves Boot 3/4 source compatibility; no SDK
        // code depends on container internals or changes host configuration.
        Object webServer=context.getClass().getMethod("getWebServer").invoke(context);
        Tomcat tomcat=(Tomcat)webServer.getClass().getMethod("getTomcat").invoke(webServer);
        AbstractHttp11Protocol<?> protocol=(AbstractHttp11Protocol<?>)tomcat.getConnector().getProtocolHandler();
        protocol.setConnectionTimeout(1000);protocol.setDisableUploadTimeout(true);
        assertThat(protocol.getConnectionTimeout()).isEqualTo(1000);
        assertThat(protocol.getDisableUploadTimeout()).isTrue();
    }
    @AfterAll void stop(){if(context!=null)context.close();}

    Socket request(byte[] body) throws Exception {
        Socket socket=new Socket("127.0.0.1",port);socket.setSoTimeout(5000);socket.setTcpNoDelay(true);
        try {
            List<Header> headers=SignedRequests.signed("POST","/echo",body,"application/json");
            StringBuilder text=new StringBuilder("POST /echo HTTP/1.1\r\nHost: api.example.test\r\n");
            for(Header header:headers)text.append(header.name()).append(": ").append(header.value()).append("\r\n");
            text.append("Content-Length: ").append(body.length).append("\r\nConnection: close\r\n\r\n");
            socket.getOutputStream().write(text.toString().getBytes(StandardCharsets.US_ASCII));return socket;
        } catch(Exception error){socket.close();throw error;}
    }
    @Test @Timeout(12)
    void idleTimeoutDoesNotEstablishAnAbsoluteUploadDeadline() throws Exception {
        byte[] body="12345678".getBytes(StandardCharsets.US_ASCII);
        var replay=context.getBean(EmbeddedHttpTest.CountingReplayStore.class);
        int before=replay.attempts.get();long started=System.nanoTime();
        try(Socket socket=request(body)) {
            for(int index=0;index<body.length;index++){
                if(index>0)Thread.sleep(250);
                socket.getOutputStream().write(body,index,1);socket.getOutputStream().flush();
            }
            String response=new String(socket.getInputStream().readAllBytes(),StandardCharsets.UTF_8);
            assertThat(TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-started)).isGreaterThan(1000);
            assertThat(response).startsWith("HTTP/1.1 200").endsWith("12345678");
            assertThat(replay.attempts).hasValue(before+1);
        }
    }
    @Test @Timeout(12)
    void hostIdleExpiryRejectsStalledUploadWithoutClaimingNonce() throws Exception {
        byte[] body="12345678".getBytes(StandardCharsets.US_ASCII);
        var replay=context.getBean(EmbeddedHttpTest.CountingReplayStore.class);int before=replay.attempts.get();
        try(Socket socket=request(body)) {
            socket.getOutputStream().write(body,0,1);socket.getOutputStream().flush();
            String response=new String(socket.getInputStream().readAllBytes(),StandardCharsets.UTF_8);
            assertThat(response).startsWith("HTTP/1.1 400").contains("{\"code\":\"INVALID_REQUEST\"}");
            assertThat(replay.attempts).hasValue(before);
        }
    }
}
