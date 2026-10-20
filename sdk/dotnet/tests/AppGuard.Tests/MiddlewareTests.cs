using System.Net;
using System.Net.Sockets;
using System.Security.Claims;
using System.Text;
using AppGuard;
using AppGuard.AspNetCore;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace AppGuard.Tests;

public class MiddlewareTests
{
    static AppGuardOptions Options(SecurityTests.Signed s,IReplayStore? replay=null,bool insecure=true,Func<HttpContext,CancellationToken,ValueTask<string?>>? auth=null,Func<HttpContext,string,SignatureParameters,CancellationToken,ValueTask<KeyRecord?>>? key=null,Func<long>? clock=null)=>new("app","https://api.example.test",replay??new InMemoryReplayStore(),auth??((_,_)=>ValueTask.FromResult<string?>("subject")),key??((_,_,_,_)=>ValueTask.FromResult<KeyRecord?>(s.Key)),clock??(()=>100),insecure);
    internal static DefaultHttpContext Context(SecurityTests.Signed s,bool target=true)
    {
        var c=new DefaultHttpContext();c.Request.Method="POST";c.Request.Scheme="http";c.Features.Get<IHttpRequestFeature>()!.RawTarget=target?s.Request.Target:null!;
        foreach(var p in s.WireHeaders)c.Request.Headers.Append(p.Name,p.Value);
        c.Request.Body=new MemoryStream(s.Request.Body.ToArray());c.Response.Body=new MemoryStream();return c;
    }
    static async Task<string> Response(DefaultHttpContext c){c.Response.Body.Position=0;return await new StreamReader(c.Response.Body).ReadToEndAsync();}
    [Fact] public async Task SchemeAndForwardedHeadersCannotFakeTlsTransport()
    {
        using var s=new SecurityTests.Signed();var c=Context(s);c.Request.Scheme="https";c.Request.Headers.Append("Forwarded","proto=https");var store=new SecurityTests.CountingStore();bool called=false;
        await new AppGuardMiddleware(_=>{called=true;return Task.CompletedTask;},Options(s,store,insecure:false)).InvokeAsync(c);
        Assert.False(called);Assert.Equal(400,c.Response.StatusCode);Assert.Equal(0,store.Count);
    }
    [Fact] public async Task MissingRawTargetFailsClosed()
    {
        using var s=new SecurityTests.Signed();var c=Context(s,false);var store=new SecurityTests.CountingStore();bool called=false;
        await new AppGuardMiddleware(_=>{called=true;return Task.CompletedTask;},Options(s,store)).InvokeAsync(c);
        Assert.False(called);Assert.Equal(400,c.Response.StatusCode);Assert.Equal("{\"code\":\"INVALID_REQUEST\"}",await Response(c));Assert.Equal(0,store.Count);
    }
    [Fact] public async Task AbsentHttpRequestFeatureFailsClosed()
    {
        using var s=new SecurityTests.Signed();var c=Context(s);var original=c.Features.Get<IHttpRequestFeature>();
        // A missing feature must never cause reconstruction from normalized paths.
        c.Features.Set<IHttpRequestFeature>(null);
        await new AppGuardMiddleware(_=>throw new Exception("downstream"),Options(s)).InvokeAsync(c);
        Assert.Equal(400,c.Response.StatusCode);c.Features.Set(original);
    }
    [Fact] public async Task TrustedClockReadAfterAuthenticationAndIdentityPreserved()
    {
        using var s=new SecurityTests.Signed();var c=Context(s);var principal=new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub","existing")],"existing-auth"));c.User=principal;
        long time=220;bool called=false;var options=Options(s,auth:(_,_)=>{time=100;return ValueTask.FromResult<string?>("subject");},clock:()=>time);
        await new AppGuardMiddleware(async ctx=>{called=true;Assert.Same(principal,ctx.User);Assert.Equal("VERIFIED",ctx.Features.Get<IAppGuardVerificationFeature>()!.Result.Code);Assert.Equal(s.Request.Body.ToArray(),await ReadAll(ctx.Request.Body));},options).InvokeAsync(c);
        Assert.True(called);
    }
    static async Task<byte[]> ReadAll(Stream stream){using var m=new MemoryStream();await stream.CopyToAsync(m);return m.ToArray();}
    [Theory] [InlineData("no-auth",401,"AUTHENTICATION_REQUIRED")] [InlineData("auth-error",503,"IDENTITY_UNAVAILABLE")] [InlineData("bad-auth",503,"IDENTITY_UNAVAILABLE")] [InlineData("unknown-key",403,"KEY_REJECTED")] [InlineData("key-error",503,"KEY_RESOLVER_UNAVAILABLE")] [InlineData("insecure",400,"INVALID_REQUEST")] [InlineData("replay-error",503,"REPLAY_STORE_UNAVAILABLE")]
    public async Task DependencyAndTransportErrorsAreRedacted(string kind,int status,string code)
    {
        using var s=new SecurityTests.Signed();var c=Context(s);var store=new SecurityTests.CountingStore{Fail=kind=="replay-error"};
        var options=Options(s,store,insecure:kind!="insecure",auth:(_,_)=>kind switch{"no-auth"=>ValueTask.FromResult<string?>(null),"auth-error"=>throw new Exception("SECRET identity"),"bad-auth"=>ValueTask.FromResult<string?>("bad subject"),_=>ValueTask.FromResult<string?>("subject")},key:(_,_,_,_)=>kind switch{"unknown-key"=>ValueTask.FromResult<KeyRecord?>(null),"key-error"=>throw new Exception("SECRET key"),_=>ValueTask.FromResult<KeyRecord?>(s.Key)});
        await new AppGuardMiddleware(_=>throw new Exception("downstream"),options).InvokeAsync(c);
        Assert.Equal(status,c.Response.StatusCode);Assert.Equal("{\"code\":\""+code+"\"}",await Response(c));if(kind!="replay-error")Assert.Equal(0,store.Count);
    }
    [Fact] public async Task BodyOverflowIncompleteStreamAndCancellationDoNotClaim()
    {
        using var s=new SecurityTests.Signed();var store=new SecurityTests.CountingStore();
        var c=Context(s);c.Request.Body=new MemoryStream(new byte[1048577]);await new AppGuardMiddleware(_=>throw new Exception(),Options(s,store)).InvokeAsync(c);Assert.Equal(413,c.Response.StatusCode);
        c=Context(s);c.Request.Headers.ContentLength=100;await new AppGuardMiddleware(_=>throw new Exception(),Options(s,store)).InvokeAsync(c);Assert.Equal(400,c.Response.StatusCode);
        c=Context(s);c.Request.Body=new BrokenBody();await new AppGuardMiddleware(_=>throw new Exception(),Options(s,store)).InvokeAsync(c);Assert.Equal(400,c.Response.StatusCode);
        c=Context(s);c.RequestAborted=new CancellationToken(true);await new AppGuardMiddleware(_=>throw new Exception(),Options(s,store)).InvokeAsync(c);Assert.NotEqual(200,c.Response.StatusCode);Assert.Equal(0,store.Count);
    }
    sealed class BrokenBody : MemoryStream { public override ValueTask<int> ReadAsync(Memory<byte> b,CancellationToken token=default)=>throw new IOException("SECRET incomplete stream"); }
    [Fact] public async Task ActualKestrelRawHttpPreservesEncodedTargetBodyAndIgnoresHostForwarding()
    {
        using var s=new SecurityTests.Signed("/encoded%2fpath?b=2&a=1");await using var server=await Start(s);var port=Port(server);
        var raw=await Send(port,s,s.Request.Target,[new("Host","untrusted.example"),new("Forwarded","proto=https;host=evil"),new("X-Forwarded-Host","evil")]);
        Assert.Contains("200 OK",raw);Assert.Contains("downstream:subject:"+Convert.ToBase64String(s.Request.Body.Span),raw);
        raw=await Send(port,s,s.Request.Target,[]);Assert.Contains("403 Forbidden",raw);Assert.Contains("REPLAY_DETECTED",raw);
    }
    [Fact] public async Task ActualKestrelExplicitEmptyQueryAndDuplicateSingleton()
    {
        using var s=new SecurityTests.Signed("/empty?");await using var server=await Start(s);var raw=await Send(Port(server),s,"/empty?",[]);Assert.Contains("200 OK",raw);
        using var t=new SecurityTests.Signed();raw=await Send(Port(server),t,t.Request.Target,[new("Authorization","Bearer duplicate")]);Assert.Contains("400 Bad Request",raw);Assert.DoesNotContain("downstream:",raw);
    }
    [Fact] public async Task ActualKestrelChunkedBodyReplayedExactly()
    {
        using var s=new SecurityTests.Signed();await using var server=await Start(s);var raw=await Send(Port(server),s,s.Request.Target,[],chunked:true);
        Assert.Contains("200 OK",raw);Assert.Contains("downstream:subject:"+Convert.ToBase64String(s.Request.Body.Span),raw);
    }
    [Fact] public async Task DownstreamExceptionPropagatesAndOriginalBodyIsRestored()
    {
        using var s=new SecurityTests.Signed();var c=Context(s);var original=c.Request.Body;
        await Assert.ThrowsAsync<InvalidOperationException>(()=>new AppGuardMiddleware(_=>throw new InvalidOperationException("application-error"),Options(s)).InvokeAsync(c));
        Assert.Same(original,c.Request.Body);
    }
    [Fact] public async Task ActualKestrelChangedTargetAndFramingRejected()
    {
        using var s=new SecurityTests.Signed();await using var server=await Start(s);var raw=await Send(Port(server),s,"/encoded%2Fpath?a=1&b=2",[]);Assert.Contains("INVALID_SIGNATURE",raw);
        raw=await Send(Port(server),s,s.Request.Target,[new("Content-Length","2")]);Assert.Contains("400 Bad Request",raw);
    }
    static async Task<WebApplication> Start(SecurityTests.Signed s)
    {
        var b=WebApplication.CreateBuilder();b.Logging.ClearProviders();b.WebHost.ConfigureKestrel(k=>k.Listen(IPAddress.Loopback,0));var app=b.Build();
        app.Use(async(c,next)=>{c.User=new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub","subject")],"existing"));await next();});
        app.UseAppGuard(Options(s,auth:(c,_)=>ValueTask.FromResult(c.User.FindFirst("sub")?.Value)));
        app.Run(async c=>{using var m=new MemoryStream();await c.Request.Body.CopyToAsync(m);await c.Response.WriteAsync("downstream:"+c.User.FindFirst("sub")!.Value+":"+Convert.ToBase64String(m.ToArray()));});await app.StartAsync();return app;
    }
    static int Port(WebApplication app)=>new Uri(app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single()).Port;
    static async Task<string> Send(int port,SecurityTests.Signed s,string target,HeaderPair[] extra,bool chunked=false)
    {
        using var tcp=new TcpClient();await tcp.ConnectAsync(IPAddress.Loopback,port);var stream=tcp.GetStream();
        var headers=new StringBuilder("POST "+target+" HTTP/1.1\r\n");foreach(var h in s.WireHeaders.Concat(extra))headers.Append(h.Name+": "+h.Value+"\r\n");
        if(!extra.Any(h=>h.Name.Equals("Host",StringComparison.OrdinalIgnoreCase)))headers.Append("Host: api.example.test\r\n");headers.Append(chunked?"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n":"Content-Length: "+s.Request.Body.Length+"\r\nConnection: close\r\n\r\n");
        await stream.WriteAsync(Encoding.ASCII.GetBytes(headers.ToString()));if(chunked)await stream.WriteAsync(Encoding.ASCII.GetBytes(s.Request.Body.Length.ToString("x",System.Globalization.CultureInfo.InvariantCulture)+"\r\n"));await stream.WriteAsync(s.Request.Body);if(chunked)await stream.WriteAsync("\r\n0\r\n\r\n"u8.ToArray());using var reader=new StreamReader(stream);return await reader.ReadToEndAsync().WaitAsync(TimeSpan.FromSeconds(10));
    }
}
