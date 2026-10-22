using System.Net;
using System.Net.Sockets;
using System.Text;
using AppGuard;
using AppGuard.AspNetCore;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Xunit;

namespace AppGuard.Tests;

/// <summary>Actual loopback HTTP/1 body-capture evidence, using the existing
/// test-only pre-parser header capture. This is not a general host ingress.</summary>
public class BodyDeadlineKestrelTests
{
    sealed class Counts : IReplayStore
    {
        internal int Entries, Authentication, Keys, Clocks, Claims, Dispatch;
        public ValueTask<bool> ClaimAsync(ReplayScope scope,long expires,long now,CancellationToken token=default)
        { Interlocked.Increment(ref Claims); return ValueTask.FromResult(true); }
    }

    static async Task<WebApplication> Start(SecurityTests.Signed signed,Counts counts,TimeSpan timeout)
    {
        var builder=WebApplication.CreateBuilder();builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(options=>options.Listen(IPAddress.Loopback,0,
            listener=>listener.Use(next=>async connection=>
            {await MiddlewareTests.CaptureHeaders(connection);await next(connection);} )));
        var app=builder.Build();
        app.Use(async(context,next)=>{Interlocked.Increment(ref counts.Entries);await next();});
        app.UseAppGuard(new AppGuardOptions("app","https://api.example.test",counts,
            (_,_)=>{Interlocked.Increment(ref counts.Authentication);return ValueTask.FromResult<string?>("subject");},
            (_,_,_,_)=>{Interlocked.Increment(ref counts.Keys);return ValueTask.FromResult<KeyRecord?>(signed.Key);},
            clock:()=>{Interlocked.Increment(ref counts.Clocks);return 100;},
            allowInsecureTransport:true,bodyReadTimeout:timeout));
        app.Run(async context=>
        {
            Interlocked.Increment(ref counts.Dispatch);
            using var copy=new MemoryStream();await context.Request.Body.CopyToAsync(copy);
            await context.Response.WriteAsync("body:"+Convert.ToBase64String(copy.ToArray()));
        });
        await app.StartAsync();return app;
    }

    static async Task<TcpClient> Connect(WebApplication app,SecurityTests.Signed signed)
    {
        var client=new TcpClient();
        try
        {
            await client.ConnectAsync(IPAddress.Loopback,MiddlewareTests.Port(app));
            var headers="POST "+signed.Request.Target+" HTTP/1.1\r\nHost: api.example.test\r\n"+
                string.Concat(signed.WireHeaders.Select(h=>h.Name+": "+h.Value+"\r\n"))+
                "Content-Length: "+signed.Request.Body.Length.ToString(System.Globalization.CultureInfo.InvariantCulture)+
                "\r\nConnection: close\r\n\r\n";
            await client.GetStream().WriteAsync(Encoding.ASCII.GetBytes(headers));return client;
        }
        catch {client.Dispose();throw;}
    }

    static async Task<string> ReadUntil(NetworkStream stream,string expected)
    {
        // Read through the response body rather than waiting for the host's
        // independent connection-drain/close policy after a rejected upload.
        var bytes=new byte[4096];var text=new StringBuilder();
        using var limit=new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while(text.Length<16384)
        {
            int count=await stream.ReadAsync(bytes,limit.Token);
            if(count==0)break;
            text.Append(Encoding.ASCII.GetString(bytes,0,count));
            if(text.ToString().Contains(expected,StringComparison.Ordinal))return text.ToString();
        }
        throw new IOException("Expected bounded HTTP response was not received");
    }

    static async Task WaitForEntry(Counts counts)
    {
        using var limit=new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while(Volatile.Read(ref counts.Entries)==0)await Task.Delay(5,limit.Token);
    }

    static async Task Stop(WebApplication app)
    {
        using var limit=new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await app.StopAsync(limit.Token);await app.DisposeAsync();
    }

    [Theory] [InlineData(false)] [InlineData(true)]
    public async Task StalledOrProgressingIncompleteUploadExpiresBeforeAnySecurityCallback(bool drip)
    {
        using var signed=new SecurityTests.Signed();var counts=new Counts();
        var app=await Start(signed,counts,TimeSpan.FromMilliseconds(200));
        using var senderStop=new CancellationTokenSource();
        Task sender=Task.CompletedTask;
        try
        {
            using var client=await Connect(app,signed);var stream=client.GetStream();
            var response=ReadUntil(stream,"{\"code\":\"INVALID_REQUEST\"}");
            if(drip)sender=Drip(stream,signed.Request.Body,senderStop.Token);
            string received=await response;
            Assert.StartsWith("HTTP/1.1 400",received);
            Assert.DoesNotContain("body:",received);
            Assert.Equal(0,counts.Authentication);Assert.Equal(0,counts.Keys);
            Assert.Equal(0,counts.Clocks);Assert.Equal(0,counts.Claims);Assert.Equal(0,counts.Dispatch);
        }
        finally
        {
            senderStop.Cancel();
            try{await sender;}catch(OperationCanceledException){}catch(IOException){}
            await Stop(app);
        }
    }

    static async Task Drip(NetworkStream stream,ReadOnlyMemory<byte> body,CancellationToken token)
    {
        for(int index=0;index<body.Length;index++)
        {
            await stream.WriteAsync(body.Slice(index,1),token);
            await Task.Delay(60,token);
        }
    }

    [Fact]
    public async Task HealthyRequestCompletesWhileAnotherBodyIsStalled()
    {
        using var signed=new SecurityTests.Signed();var counts=new Counts();
        var app=await Start(signed,counts,TimeSpan.FromMilliseconds(700));
        try
        {
            using var blocked=await Connect(app,signed);
            var denied=ReadUntil(blocked.GetStream(),"{\"code\":\"INVALID_REQUEST\"}");
            await WaitForEntry(counts);
            using var healthy=await Connect(app,signed);
            await healthy.GetStream().WriteAsync(signed.Request.Body);
            string expected="body:"+Convert.ToBase64String(signed.Request.Body.Span);
            string allowed=await ReadUntil(healthy.GetStream(),expected);
            Assert.StartsWith("HTTP/1.1 200",allowed);
            Assert.Contains(expected,allowed);
            Assert.StartsWith("HTTP/1.1 400",await denied);
            Assert.Equal(1,counts.Authentication);Assert.Equal(1,counts.Keys);
            Assert.Equal(1,counts.Clocks);Assert.Equal(1,counts.Claims);Assert.Equal(1,counts.Dispatch);
        }
        finally{await Stop(app);}
    }
}
