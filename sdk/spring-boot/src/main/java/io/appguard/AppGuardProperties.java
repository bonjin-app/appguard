package io.appguard;
import org.springframework.boot.context.properties.ConfigurationProperties;
@ConfigurationProperties("appguard")
public final class AppGuardProperties {
    private String appId,origin;
    private boolean allowInsecureTransport;
    public String getAppId(){return appId;}public void setAppId(String value){appId=value;}
    public String getOrigin(){return origin;}public void setOrigin(String value){origin=value;}
    public boolean isAllowInsecureTransport(){return allowInsecureTransport;}public void setAllowInsecureTransport(boolean value){allowInsecureTransport=value;}
}
