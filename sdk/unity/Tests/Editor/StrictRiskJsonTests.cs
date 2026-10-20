using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using NUnit.Framework;

namespace AppGuard.Tests {
public class StrictRiskJsonTests {
    static string Good => new JObject { ["ok"]=true, ["result"]=JObject.Parse(File.ReadAllText(Path.Combine(UnityEditor.PackageManager.PackageInfo.FindForAssembly(typeof(Client).Assembly).resolvedPath,"Tests/Editor/local-risk-bridge.json")))["reports"][0]["report"].DeepClone() }.ToString(Formatting.None);
    sealed class Wire : INativeTransport {
        readonly string response;
        internal Wire(string response) {this.response=response;}
        public string Invoke(string operation,string payload) {Assert.That(operation,Is.EqualTo("scanLocalRisk"));return response;}
    }
    static string Error(string detail) => "{\"ok\":false,\"error\":{\"code\":\"APPGUARD_UNSUPPORTED\",\"detail\":"+detail+"}}";
    static void Reject(string text) {
        var error=Assert.Throws<AppGuardException>(()=>new Client(new Wire(text)).ScanLocalRiskAsync().GetAwaiter().GetResult());
        Assert.That(error.Code,Is.EqualTo("APPGUARD_OPERATION_FAILED"));Assert.That(error.Message,Is.EqualTo(error.Code));Assert.That(error.InnerException,Is.Null);
    }
    static IEnumerable<TestCaseData> InvalidResponses() {
        yield return new TestCaseData(Good.Replace('"','\'')).SetName("StrictJson_SingleQuotes");
        yield return new TestCaseData(Good.Replace("\"ok\":","ok:")).SetName("StrictJson_UnquotedKey");
        yield return new TestCaseData(Good.Insert(Good.Length-1,",")).SetName("StrictJson_TrailingRootComma");
        yield return new TestCaseData(Good.Replace("\"state\":\"not_observed\"}","\"state\":\"not_observed\",}")).SetName("StrictJson_TrailingCheckComma");
        yield return new TestCaseData(Good.Replace("],\"riskSignals\"",",],\"riskSignals\"")).SetName("StrictJson_TrailingArrayComma");
        yield return new TestCaseData("/*PRIVATE*/"+Good).SetName("StrictJson_LeadingBlockComment");
        yield return new TestCaseData("//PRIVATE\n"+Good).SetName("StrictJson_LeadingLineComment");
        yield return new TestCaseData(Good.Replace("\"result\":","\"result\":/*PRIVATE*/")).SetName("StrictJson_NestedComment");
        yield return new TestCaseData(Good.Replace("},{","},/*PRIVATE*/{")).SetName("StrictJson_ArrayComment");
        yield return new TestCaseData(Good+"/*PRIVATE*/").SetName("StrictJson_TrailingComment");
        foreach(var c in new[]{'\v','\f','\u00a0','\ufeff','\u2028'})
            yield return new TestCaseData("{"+c+Good.Substring(1)).SetName("StrictJson_NonJsonWhitespace_"+((int)c).ToString("x4"));
        foreach(var token in new[]{"+1","01","-01","0x10","1.",".1","NaN","Infinity","-Infinity","undefined","new Date(0)","1e","1e+","--1","truefalse","[1,]","{\"a\":1,}"})
            yield return new TestCaseData(Error(token)).SetName("StrictJson_NonJsonValue_"+token.Replace('"','_'));
        foreach(char c in new[]{'\0','\t','\n','\r','\u001f'})
            yield return new TestCaseData(Error("\"PRIVATE"+c+"text\"")).SetName("StrictJson_RawControl_"+((int)c).ToString("x2"));
        int badString=0;
        foreach(var text in new[]{"\"\\x41\"","\"\\q\"","\"\\u123\"","\"\\uZZZZ\"","\"unterminated","\"\\uD800\"","\"\\uDC00\"","\"\\uD800\\u0041\"","\"\\uDC00\\uD800\"","\""+'\ud800'+"\"","\""+'\udc00'+"\""})
            yield return new TestCaseData(Error(text)).SetName("StrictJson_BadString_"+(badString++));
        yield return new TestCaseData(Good+" {}").SetName("StrictJson_MultipleValues");
        yield return new TestCaseData(Good.Replace("\"ok\":true","\"ok\":true,\"\\u006fk\":true")).SetName("StrictJson_DecodedDuplicate");
    }
    [TestCaseSource(nameof(InvalidResponses))] public void NonJsonAndMalformedResponsesRejectWithFixedError(string text) {Reject(text);}
    [Test] public void LegalWhitespaceAndEscapedReportKeysAndValuesRemainAccepted() {
        foreach(var text in new[]{Good," \t\r\n"+Good+"\r\n\t ",Good.Replace("\"schema\"","\"\\u0073chema\"").Replace("\"android\"","\"andr\\u006fid\""),Good.Replace(":"," \t:\r\n").Replace(",",",\t\n")}) {
            var report=new Client(new Wire(text)).ScanLocalRiskAsync().GetAwaiter().GetResult();Assert.That(report.Platform,Is.EqualTo("android"));Assert.That(report.Checks.Count,Is.EqualTo(7));
        }
    }
    [TestCase("0")][TestCase("-0")][TestCase("123")][TestCase("-123")][TestCase("1.25")][TestCase("0.5")][TestCase("1e2")][TestCase("1E+2")][TestCase("-1.5e-2")][TestCase("true")][TestCase("false")][TestCase("null")][TestCase("[]")][TestCase("{}")]
    public void StandardJsonValuesInIgnoredErrorDetailsPreserveFixedCode(string value) {
        var error=Assert.Throws<AppGuardException>(()=>new Client(new Wire(Error(value))).ScanLocalRiskAsync().GetAwaiter().GetResult());Assert.That(error.Code,Is.EqualTo("APPGUARD_UNSUPPORTED"));Assert.That(error.InnerException,Is.Null);
    }
    [Test] public void CommentMarkersEscapesAndUnicodeInsideStringsAreNotSyntax() {
        foreach(var value in new[]{"\"/*PRIVATE*/ // still a string, } ]\"","\"quote\\\" slash\\/ backslash\\\\ controls\\b\\f\\n\\r\\t\"","\"\\u0041\\u00E9\\uD83D\\uDE80\"","\"한글 🚀\u2028\u007f\""}) {
            var error=Assert.Throws<AppGuardException>(()=>new Client(new Wire(Error(value))).ScanLocalRiskAsync().GetAwaiter().GetResult());Assert.That(error.Code,Is.EqualTo("APPGUARD_UNSUPPORTED"));Assert.That(error.Message,Is.EqualTo(error.Code));
        }
    }
    [Test] public void ContainerDepthAndResponseBoundsStayBounded() {
        var accepted=Error(new string('[',14)+"null"+new string(']',14));
        Assert.That(Assert.Throws<AppGuardException>(()=>new Client(new Wire(accepted)).ScanLocalRiskAsync().GetAwaiter().GetResult()).Code,Is.EqualTo("APPGUARD_UNSUPPORTED"));
        Reject(Error(new string('[',15)+"null"+new string(']',15)));
        Reject(Error(new string('[',1000)+"null"+new string(']',1000)));
        new Client(new Wire(Good.PadRight(4096))).ScanLocalRiskAsync().GetAwaiter().GetResult();Reject(Good.PadRight(4097));
        Reject(Error("\""+new string('é',2048)+"\""));
    }
}
}
