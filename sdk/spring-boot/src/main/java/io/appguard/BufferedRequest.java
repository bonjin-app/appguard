package io.appguard;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.*;
import java.nio.charset.*;
/** Blocking servlet body replay. Forms/multipart are rejected before this wrapper is installed. */
final class BufferedRequest extends HttpServletRequestWrapper {
    private final byte[] body;
    private final HttpServletResponse response;
    private ServletInputStream stream;
    private BufferedReader reader;
    BufferedRequest(HttpServletRequest request,HttpServletResponse response,byte[] body){super(request);this.response=response;this.body=body;}
    @Override public AsyncContext startAsync(){
        // The inherited no-argument method loses this body wrapper at the container boundary.
        // Use the explicit overload so worker code and redispatch retain the verified request.
        return super.startAsync(this,response);
    }
    // Keep the inherited two-argument overload: caller-supplied request/response wrappers
    // must reach the container unchanged rather than being silently replaced here.
    @Override public ServletInputStream getInputStream(){
        if(reader!=null) throw new IllegalStateException("Reader already obtained");
        if(stream==null) stream=new ReplayInputStream(body);return stream;
    }
    @Override public BufferedReader getReader() throws IOException {
        if(stream!=null) throw new IllegalStateException("Input stream already obtained");
        if(reader==null){String encoding=getCharacterEncoding();reader=new BufferedReader(new InputStreamReader(new ByteArrayInputStream(body),encoding==null?StandardCharsets.ISO_8859_1:Charset.forName(encoding)));}return reader;
    }
    @Override public long getContentLengthLong(){return body.length;}
    @Override public int getContentLength(){return body.length;}
    private static final class ReplayInputStream extends ServletInputStream {
        private final ByteArrayInputStream input;
        ReplayInputStream(byte[] body){input=new ByteArrayInputStream(body);}
        @Override public int read(){return input.read();}
        @Override public int read(byte[] b,int off,int len){return input.read(b,off,len);}
        @Override public boolean isFinished(){return input.available()==0;}
        @Override public boolean isReady(){return true;}
        @Override public void setReadListener(ReadListener listener){throw new IllegalStateException("Nonblocking servlet input is not supported by AppGuard v0");}
    }
}
