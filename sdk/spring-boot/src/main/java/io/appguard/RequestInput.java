package io.appguard;
import java.util.List;
/** Exact origin-form target and raw content bytes, before parsing or decompression. */
public record RequestInput(String method, String target, List<Header> headers, byte[] body) {
    public RequestInput { if(headers!=null) headers=List.copyOf(headers); if(body!=null) body=body.clone(); }
    @Override public byte[] body() { return body==null ? null : body.clone(); }
    @Override public String toString(){return "RequestInput[redacted]";}
}
