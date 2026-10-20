package io.appguard;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.*;
import java.time.Clock;
import java.util.*;

/** Protect every request reaching this filter, after existing authentication and before body parsing. */
public final class AppGuardFilter implements Filter {
    public static final String VERIFICATION_ATTRIBUTE="io.appguard.verification";
    private final String appId,origin;
    private final IdentityResolver identities;
    private final ReplayStore replay;
    private final Clock clock;
    private final boolean allowInsecureTransport;
    private final String stateAttribute=AppGuardFilter.class.getName()+".verified."+UUID.randomUUID();
    private record State(byte[] body,VerificationResult result){}
    public AppGuardFilter(String appId,String origin,IdentityResolver identities,ReplayStore replay,Clock clock,boolean allowInsecureTransport){
        if(!Canonical.validIdentifier(appId)) throw new IllegalArgumentException("A valid configured AppGuard app ID is required");
        try{Canonical.validateOrigin(origin);}catch(VerificationException e){throw new IllegalArgumentException("A valid configured external HTTPS origin is required");}
        this.appId=appId;this.origin=origin;this.identities=Objects.requireNonNull(identities,"IdentityResolver required");this.replay=Objects.requireNonNull(replay,"ReplayStore required");this.clock=Objects.requireNonNull(clock,"Clock required");this.allowInsecureTransport=allowInsecureTransport;
    }
    @Override public void doFilter(ServletRequest input,ServletResponse output,FilterChain chain) throws IOException,ServletException {
        if(!(input instanceof HttpServletRequest request) || !(output instanceof HttpServletResponse response)) throw new ServletException("HTTP request/response required");
        // Redispatch can reuse only proof attached by this exact filter to the original verified request.
        if(request.getDispatcherType()!=DispatcherType.REQUEST){
            Object prior=request.getAttribute(stateAttribute);
            if(!(prior instanceof State state)){failure(response,400,"INVALID_REQUEST");return;}
            request.setAttribute(VERIFICATION_ATTRIBUTE,state.result());chain.doFilter(new BufferedRequest(request,response,state.body()),response);return;
        }
        HttpServletRequest raw=original(request);
        if(!allowInsecureTransport && !raw.isSecure()){failure(response,400,"INVALID_REQUEST");return;}
        List<Header> headers;ParsedSignature parsed;String target;byte[] body;
        try{
            headers=captureHeaders(raw);parsed=Wire.parse(headers);
            String uri=raw.getRequestURI(), query=raw.getQueryString();
            Canonical.require(uri!=null && !uri.isEmpty(),"INVALID_REQUEST");target=uri+(query==null?"":"?"+query);Canonical.validateTarget(target);
            Map<String,String> values=Canonical.headers(headers,true);
            String media=values.get("content-type").split(";",2)[0].toLowerCase(Locale.ROOT).trim();
            Canonical.require(!media.equals("application/x-www-form-urlencoded") && !media.startsWith("multipart/"),"INVALID_REQUEST");
            String length=values.get("content-length");
            if(length!=null && (length.length()>7 || (length.length()==7 && length.compareTo(Integer.toString(Canonical.MAX_BODY))>0))){failure(response,413,"INVALID_REQUEST");return;}
            body=captureBody(raw.getInputStream());
            if(body.length>Canonical.MAX_BODY){failure(response,413,"INVALID_REQUEST");return;}
            Wire.validateCapturedLength(headers,body.length);
        }catch(VerificationException e){failure(response,status(e.code()),e.code());return;}
        catch(IOException | RuntimeException e){failure(response,400,"INVALID_REQUEST");return;}
        Identity identity;
        try{identity=identities.resolve(request,parsed.parameters());}
        catch(VerificationException e){String code=e.code().equals("KEY_RESOLVER_UNAVAILABLE")?"KEY_RESOLVER_UNAVAILABLE":"IDENTITY_UNAVAILABLE";failure(response,503,code);return;}
        catch(Exception e){failure(response,503,"IDENTITY_UNAVAILABLE");return;}
        if(identity==null){failure(response,401,"AUTHENTICATION_REQUIRED");return;}
        if(!Canonical.validIdentifier(identity.subject()) || (identity.key()!=null && !identity.key().validResolverContract())){failure(response,503,"IDENTITY_UNAVAILABLE");return;}
        VerificationResult result;
        try{
            // Time is sampled exactly once, only after authentication completes.
            long now=clock.instant().getEpochSecond();
            result=Verifier.verify(new RequestInput(raw.getMethod(),target,headers,body),parsed.parameters(),parsed.signature(),origin,appId,identity.subject(),identity.key(),now,replay);
        }catch(VerificationException e){failure(response,status(e.code()),e.code());return;}
        catch(RuntimeException e){failure(response,503,"IDENTITY_UNAVAILABLE");return;}
        request.setAttribute(stateAttribute,new State(body,result));request.setAttribute(VERIFICATION_ATTRIBUTE,result);
        chain.doFilter(new BufferedRequest(request,response,body),response);
    }
    private static HttpServletRequest original(HttpServletRequest request){
        while(request instanceof HttpServletRequestWrapper wrapper && wrapper.getRequest() instanceof HttpServletRequest next) request=next;
        return request;
    }
    private static List<Header> captureHeaders(HttpServletRequest request){
        Enumeration<String> names=request.getHeaderNames();Canonical.require(names!=null,"INVALID_REQUEST");List<Header> result=new ArrayList<>();int size=0;
        while(names.hasMoreElements()){
            String name=names.nextElement();Canonical.require(name!=null,"INVALID_REQUEST");Enumeration<String> values=request.getHeaders(name);Canonical.require(values!=null,"INVALID_REQUEST");
            while(values.hasMoreElements()){
                String value=values.nextElement();Canonical.require(value!=null,"INVALID_REQUEST");size+=name.length()+value.length();
                Canonical.require(result.size()<64 && size<=16384,"INVALID_REQUEST");result.add(new Header(name,value));
            }
        }
        return result;
    }
    private static byte[] captureBody(ServletInputStream stream) throws IOException {
        if(stream==null) throw Canonical.fail("INVALID_REQUEST");
        ByteArrayOutputStream output=new ByteArrayOutputStream();byte[] chunk=new byte[8192];int count;
        while(output.size()<=Canonical.MAX_BODY){
            count=stream.read(chunk,0,Math.min(chunk.length,Canonical.MAX_BODY+1-output.size()));
            if(count<0)break;if(count==0){int b=stream.read();if(b<0)break;output.write(b);}else output.write(chunk,0,count);
        }
        return output.toByteArray();
    }
    private static int status(String code){return switch(code){case "INVALID_REQUEST"->400;case "REPLAY_STORE_UNAVAILABLE"->503;default->403;};}
    private static void failure(HttpServletResponse response,int status,String code) throws IOException {
        response.setStatus(status);response.setContentType("application/json");response.setCharacterEncoding("UTF-8");response.getWriter().write("{\"code\":\""+code+"\"}");
    }
}
