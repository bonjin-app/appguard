using System;
using System.Text;

namespace AppGuard {
/// <summary>Syntax-only JSON validation before JSON.NET's semantic decoding.
/// Bounded to the risk envelope profile; rejects extension syntax and ill-formed Unicode.
/// Duplicate decoded keys and report semantics remain checked by LocalRiskDecoder.</summary>
internal static class StrictRiskJson {
    internal static void Validate(string text) {
        if(text==null || text.Length>LocalRiskDecoder.MaxBytes || Encoding.UTF8.GetByteCount(text)>LocalRiskDecoder.MaxBytes)
            throw new FormatException();
        new Parser(text).Validate();
    }
    sealed class Parser {
        readonly string text;
        int at;
        internal Parser(string text) {this.text=text;}
        internal void Validate() {Value(0);Whitespace();if(at!=text.Length)throw new FormatException();}
        void Whitespace() {
            while(at<text.Length) {
                char c=text[at];if(c!=' ' && c!='\t' && c!='\r' && c!='\n')return;
                at++;
            }
        }
        bool Take(char c) {if(at>=text.Length || text[at]!=c)return false;at++;return true;}
        void Expect(char c) {if(!Take(c))throw new FormatException();}
        void Value(int depth) {
            Whitespace();if(at==text.Length)throw new FormatException();
            switch(text[at]) {
                case '{':Object(depth+1);return;
                case '[':Array(depth+1);return;
                case '"':Quoted();return;
                case 't':Literal("true");return;
                case 'f':Literal("false");return;
                case 'n':Literal("null");return;
                default:
                    if(text[at]=='-' || Digit(text[at])) {Number();return;}
                    throw new FormatException();
            }
        }
        void Object(int depth) {
            if(depth>16)throw new FormatException();
            Expect('{');Whitespace();if(Take('}'))return;
            while(true) {
                Quoted();Whitespace();Expect(':');Value(depth);Whitespace();
                if(Take('}'))return;
                Expect(',');Whitespace();
            }
        }
        void Array(int depth) {
            if(depth>16)throw new FormatException();
            Expect('[');Whitespace();if(Take(']'))return;
            while(true) {
                Value(depth);Whitespace();if(Take(']'))return;
                Expect(',');
            }
        }
        void Literal(string word) {foreach(char c in word)Expect(c);}
        static bool Digit(char c) => c>='0' && c<='9';
        void Digits() {
            if(at==text.Length || !Digit(text[at]))throw new FormatException();
            do {at++;}while(at<text.Length && Digit(text[at]));
        }
        void Number() {
            Take('-');
            if(Take('0')) {if(at<text.Length && Digit(text[at]))throw new FormatException();}
            else Digits();
            if(Take('.'))Digits();
            if(Take('e') || Take('E')) {if(!Take('+'))Take('-');Digits();}
        }
        int HexUnit() {
            if(text.Length-at<4)throw new FormatException();
            int value=0;
            for(int i=0;i<4;i++) {
                char c=text[at++];int digit=c>='0' && c<='9'?c-'0':c>='a' && c<='f'?c-'a'+10:c>='A' && c<='F'?c-'A'+10:-1;
                if(digit<0)throw new FormatException();value=value*16+digit;
            }
            return value;
        }
        void Quoted() {
            Expect('"');
            while(at<text.Length) {
                char c=text[at++];if(c=='"')return;
                if(c<32)throw new FormatException();
                if(c=='\\') {
                    if(at==text.Length)throw new FormatException();
                    char escape=text[at++];
                    switch(escape) {
                        case '"':case '\\':case '/':case 'b':case 'f':case 'n':case 'r':case 't':break;
                        case 'u':
                            char unit=(char)HexUnit();
                            if(char.IsHighSurrogate(unit)) {
                                Expect('\\');Expect('u');if(!char.IsLowSurrogate((char)HexUnit()))throw new FormatException();
                            } else if(char.IsLowSurrogate(unit))throw new FormatException();
                            break;
                        default:throw new FormatException();
                    }
                } else if(char.IsHighSurrogate(c)) {
                    if(at==text.Length || !char.IsLowSurrogate(text[at++]))throw new FormatException();
                } else if(char.IsLowSurrogate(c))throw new FormatException();
            }
            throw new FormatException();
        }
    }
}
}
