import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.*;

/** Fixed diagnostic modes only; never accepts a filesystem root or command. */
public final class AppGuardRuntimeInventory {
    private static final Path ROOT=Path.of("/opt/java/openjdk");
    private static final int MAX=8*1024*1024;
    private static final String FORMAT="%{NAME}\\t%{EPOCHNUM}\\t%{VERSION}\\t%{RELEASE}\\t%{ARCH}\\t%{SOURCERPM}\\t%{LICENSE}\\n";
    private static final LinkOption[] NOFOLLOW={LinkOption.NOFOLLOW_LINKS};
    private static final String PATH="/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    private AppGuardRuntimeInventory() {}
    record Hashed(String sha256,long size,String header) {}
    record Command(int code,String text) {}
    static final class Unverified extends IOException {
        final String reason;
        Unverified(String reason){super("unverified");this.reason=reason;}
    }
    private static void require(boolean value)throws IOException {if(!value)throw new Unverified("protocol_unverified");}
    private static String hex(byte[] bytes){return HexFormat.of().formatHex(bytes);}
    private static BasicFileAttributes attributes(Path path)throws IOException {
        BasicFileAttributes row=Files.readAttributes(path,BasicFileAttributes.class,NOFOLLOW);
        require(row.isRegularFile() && row.fileKey()!=null);return row;
    }
    static Hashed hash(Path path,long maximum)throws Exception {
        BasicFileAttributes before=attributes(path);require(before.size()<=maximum);
        MessageDigest digest=MessageDigest.getInstance("SHA-256");ByteArrayOutputStream header=new ByteArrayOutputStream(20);
        long size=0;
        try(SeekableByteChannel channel=Files.newByteChannel(path,Set.of(StandardOpenOption.READ,LinkOption.NOFOLLOW_LINKS))){
            ByteBuffer buffer=ByteBuffer.allocate(65536);
            while(channel.read(buffer)!=-1){buffer.flip();int count=buffer.remaining();size+=count;require(size<=maximum);
                byte[] bytes=new byte[count];buffer.get(bytes);digest.update(bytes);
                if(header.size()<20)header.write(bytes,0,Math.min(20-header.size(),bytes.length));buffer.clear();}
        }
        BasicFileAttributes after=attributes(path);
        require(size==before.size() && before.size()==after.size() && before.fileKey().equals(after.fileKey())
            && before.lastModifiedTime().equals(after.lastModifiedTime()) && before.creationTime().equals(after.creationTime()));
        return new Hashed(hex(digest.digest()),size,header.size()==0?"-":hex(header.toByteArray()));
    }
    private static String small(Path path,int maximum)throws IOException {
        try(InputStream stream=Files.newInputStream(path)){
            byte[] bytes=stream.readNBytes(maximum+1);require(bytes.length<=maximum);
            return StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes)).toString();
        }
    }
    private static String field(String value)throws IOException {
        require(value!=null && value.length()<=4096 && value.chars().noneMatch(c->c<32 || c==127));return value;
    }
    static String tree(Path root,String os,String version,int uid)throws Exception {
        StringBuilder result=new StringBuilder("JRI\t1\nOS_ID\t"+field(os)+"\nOS_VERSION\t"+field(version)+"\nARCH\t"
            +(System.getProperty("os.arch").equals("amd64")?"x86_64":"aarch64")+"\nUID\t"+uid+"\n");
        int[] counts={0,0,0,0};long[] total={0};
        Files.walkFileTree(root,new SimpleFileVisitor<Path>(){
            @Override public FileVisitResult preVisitDirectory(Path directory,BasicFileAttributes attrs)throws IOException {
                require(++counts[3]<=8192);return FileVisitResult.CONTINUE;
            }
            @Override public FileVisitResult visitFile(Path file,BasicFileAttributes attrs)throws IOException {
                try {
                    require(counts[0]+counts[1]<4096);String name=field(root.relativize(file).toString());
                    if(attrs.isSymbolicLink()){
                        String target=field(Files.readSymbolicLink(file).toString());
                        result.append("SYMLINK\t").append(name).append('\t').append(target).append('\n');counts[1]++;
                    }else {
                        require(attrs.isRegularFile());Hashed row=hash(file,512L*1024*1024);total[0]+=row.size();require(total[0]<=1024L*1024*1024);
                        result.append("FILE\t").append(name).append('\t').append(row.sha256()).append('\t').append(row.size()).append('\t').append(row.header()).append('\n');counts[0]++;
                        if(row.header().startsWith("7f454c46")){require(++counts[2]<=256);}
                    }
                    require(result.length()<=MAX);return FileVisitResult.CONTINUE;
                }catch(IOException error){throw error;}catch(Exception error){throw new Unverified("read_unavailable");}
            }
        });
        result.append("JAVA_BEGIN\t0\n");
        for(String key:List.of("java.vendor","java.version","java.runtime.version","os.arch"))
            result.append("JAVA\t    ").append(key).append(" = ").append(field(System.getProperty(key))).append('\n');
        result.append("JAVA_END\nRELEASE_BEGIN\n");
        for(String line:small(root.resolve("release"),65536).split("\\R"))result.append("RELEASE\t").append(field(line)).append('\n');
        result.append("RELEASE_END\nEND\t").append(counts[0]).append('\t').append(counts[1]).append('\t').append(counts[2]).append('\n');
        require(result.length()<=MAX);return result.toString();
    }
    private static List<Integer> ids(String status,String name)throws IOException {
        List<Integer> result=null;
        for(String line:status.split("\\R"))if(line.startsWith(name+":")){
            require(result==null);String[] fields=line.substring(name.length()+1).strip().split("\\s+");require(fields.length==4);
            result=new ArrayList<>();for(String field:fields){require(field.matches("[0-9]{1,10}"));int n=Integer.parseInt(field);require(n==10001);result.add(n);}
        }
        require(result!=null);return result;
    }
    private static String executable(Path proc)throws Exception {
        Path expected=ROOT.resolve("bin/java").toRealPath(),actual=proc.toRealPath();
        require(expected.startsWith(ROOT) && actual.equals(expected));
        byte[] bytes;
        try(InputStream stream=Files.newInputStream(proc)){bytes=stream.readNBytes(20);}
        require(bytes.length==20 && bytes[0]==127 && bytes[1]=='E' && bytes[2]=='L' && bytes[3]=='F'
            && bytes[4]==2 && bytes[5]==1 && (bytes[16]==2 || bytes[16]==3) && bytes[17]==0);
        int machine=(bytes[18]&255)|((bytes[19]&255)<<8);require(machine==62 || machine==183);return hex(bytes);
    }
    private static Map<String,Object> identity()throws Exception {
        String status=small(Path.of("/proc/self/status"),16384);Map<String,Object> result=new LinkedHashMap<>();
        result.put("uids",ids(status,"Uid"));result.put("gids",ids(status,"Gid"));
        result.put("pid1_elf",executable(Path.of("/proc/1/exe")));result.put("self_elf",executable(Path.of("/proc/self/exe")));
        result.put("java_vendor",System.getProperty("java.vendor"));result.put("java_version",System.getProperty("java.version"));
        result.put("java_runtime_version",System.getProperty("java.runtime.version"));result.put("os_arch",System.getProperty("os.arch"));return result;
    }
    private static Map<String,String> osRelease()throws IOException {
        Map<String,String> result=new HashMap<>();
        for(String row:small(Path.of("/etc/os-release"),16384).split("\\R")){
            int index=row.indexOf('=');if(index<1)continue;String key=row.substring(0,index),value=row.substring(index+1);
            if(value.startsWith("\"") && value.endsWith("\""))value=value.substring(1,value.length()-1);
            if(key.equals("ID") || key.equals("VERSION_ID")){require(!result.containsKey(key));result.put(key,field(value));}
        }
        require(result.keySet().equals(Set.of("ID","VERSION_ID")));return result;
    }
    private static List<Object> databases()throws Exception {
        List<Object> result=new ArrayList<>();Set<Path> seen=new HashSet<>();
        for(String prefix:List.of("/usr/lib/sysimage/rpm","/var/lib/rpm")){
            Path directory=Path.of(prefix);if(!Files.exists(directory))continue;
            Path real=directory.toRealPath();require(real.equals(Path.of("/usr/lib/sysimage/rpm")) || real.equals(Path.of("/var/lib/rpm")));
            if(!seen.add(real))continue;
            for(String name:List.of("rpmdb.sqlite","rpmdb.sqlite-wal","rpmdb.sqlite-shm","Packages")){
                Path file=real.resolve(name);if(!Files.exists(file,NOFOLLOW))continue;
                Hashed row=hash(file,64L*1024*1024);
                result.add(Map.of("tag",(real.startsWith("/usr")?"usr-":"var-")+name,"sha256",row.sha256(),"size",row.size()));
            }
        }
        if(result.isEmpty())throw new Unverified("read_unavailable");return result;
    }
    static ProcessBuilder builder(List<String> command){
        ProcessBuilder builder=new ProcessBuilder(command);Map<String,String> env=builder.environment();
        Map<String,String> homes=new HashMap<>();for(String key:List.of("HOME","CODEX_HOME"))if(env.containsKey(key))homes.put(key,env.get(key));
        env.clear();env.putAll(homes);env.put("PATH",PATH);env.put("LC_ALL","C");return builder;
    }
    private static String tool(String name)throws IOException {
        for(String candidate:List.of("/usr/bin/"+name,"/bin/"+name))if(Files.isRegularFile(Path.of(candidate)) && Files.isExecutable(Path.of(candidate)))return candidate;
        throw new Unverified("tool_unavailable");
    }
    static Command command(List<String> args,int maximum,int seconds)throws Exception {
        Process process=builder(args).redirectError(ProcessBuilder.Redirect.DISCARD).start();
        Set<ProcessHandle> children=new HashSet<>();ExecutorService reader=Executors.newSingleThreadExecutor(task->{Thread thread=new Thread(task,"appguard-fixed-query");thread.setDaemon(true);return thread;});
        Future<byte[]> output=reader.submit(()->{try(InputStream stream=process.getInputStream()){byte[] bytes=stream.readNBytes(maximum+1);if(bytes.length>maximum)throw new Unverified("output_limit");return bytes;}});
        try {
            process.getOutputStream().close();long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(seconds);
            while(process.isAlive() && System.nanoTime()<deadline){process.descendants().forEach(children::add);process.waitFor(10,TimeUnit.MILLISECONDS);}
            if(process.isAlive())throw new Unverified("timeout");
            byte[] bytes=output.get(Math.max(1,deadline-System.nanoTime()),TimeUnit.NANOSECONDS);
            return new Command(process.exitValue(),StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes)).toString());
        }catch(TimeoutException error){throw new Unverified("timeout");}
        catch(ExecutionException error){
            if(error.getCause() instanceof Unverified known)throw known;
            throw new Unverified("read_unavailable");
        }finally {
            process.descendants().forEach(children::add);
            for(ProcessHandle child:children)if(child.isAlive())child.destroyForcibly();if(process.isAlive())process.destroyForcibly();
            long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(2);
            while((process.isAlive() || children.stream().anyMatch(ProcessHandle::isAlive)) && System.nanoTime()<end)Thread.sleep(10);
            output.cancel(true);reader.shutdownNow();reader.awaitTermination(500,TimeUnit.MILLISECONDS);
            if(process.isAlive() || children.stream().anyMatch(ProcessHandle::isAlive) || !reader.isTerminated())throw new Unverified("resource_unverified");
        }
    }
    private static String packages(String file)throws Exception {
        List<String> args=new ArrayList<>(List.of(tool("rpm"),file==null?"-qa":"-qf","--queryformat",FORMAT));
        if(file!=null)args.addAll(List.of("--",file));Command result=command(args,2*1024*1024,30);
        if(result.code()!=0)throw new Unverified("query_failed");return result.text();
    }
    private static String relative(String value)throws IOException {
        require(value.matches("[A-Za-z0-9][A-Za-z0-9._+@/-]{0,255}") && !List.of(value.split("/",-1)).stream().anyMatch(s->s.isEmpty() || s.equals(".") || s.equals("..")));return value;
    }
    private static String library(String value)throws IOException {
        require(value.length()<=512 && value.matches("/[A-Za-z0-9._+@/:-]+") && Path.of(value).normalize().toString().equals(value));
        require(List.of("/lib/","/lib64/","/usr/lib/","/usr/lib64/","/usr/local/lib/",ROOT+"/").stream().anyMatch(value::startsWith));return value;
    }
    private static List<Object> linkage(String[] args)throws Exception {
        require(args.length>1 && args.length<=257);String ldd=tool("ldd");List<Object> result=new ArrayList<>();Set<String> seen=new HashSet<>();
        for(int i=1;i<args.length;i++){
            String name=relative(args[i]);require(seen.add(name));Path file=ROOT.resolve(name);Hashed row=hash(file,512L*1024*1024);require(row.header().startsWith("7f454c46"));
            Command response=command(List.of(ldd,file.toString()),2*1024*1024,30);
            result.add(Map.of("path",name,"code",response.code(),"lines",List.of(response.text().split("\\R"))));
        }
        return result;
    }
    private static List<Object> providers(String[] args)throws Exception {
        require(args.length<=257);List<Object> result=new ArrayList<>();Set<String> seen=new HashSet<>();
        for(int i=1;i<args.length;i++){
            String name=library(args[i]);require(seen.add(name));String real=library(Path.of(name).toRealPath().toString());Hashed file=hash(Path.of(real),512L*1024*1024);
            result.add(Map.of("path",name,"real",real,"sha256",file.sha256(),"owners",packages(real)));
        }
        return result;
    }
    static String featureJson(AppGuardRuntimeProbe.ProbeResult result)throws IOException {
        Map<String,Object> checks=new LinkedHashMap<>();boolean passed=true;
        for(String name:AppGuardRuntimeProbe.names()){
            boolean entered=result.entered().get(name),success=result.checks().get(name);passed&=entered && success;
            Map<String,Object> row=new LinkedHashMap<>();row.put("attempted",entered);row.put("passed",entered?success:null);checks.put(name,row);
        }
        return json(Map.of("schema",2,"checks",checks,"checks_passed",passed,"result_code",result.code(),"passed",passed && result.code()==0));
    }
    private static String json(Object value)throws IOException {
        if(value==null)return "null";
        if(value instanceof Boolean || value instanceof Integer || value instanceof Long)return value.toString();
        if(value instanceof String text){StringBuilder result=new StringBuilder("\"");for(char c:text.toCharArray()){
            if(c=='"' || c=='\\')result.append('\\').append(c);else if(c<32 || c==127)result.append(String.format("\\u%04x",(int)c));else result.append(c);
        }return result.append('"').toString();}
        if(value instanceof Map<?,?> map){List<String> rows=new ArrayList<>();for(var row:map.entrySet())rows.add(json(row.getKey())+":"+json(row.getValue()));return "{"+String.join(",",rows)+"}";}
        if(value instanceof List<?> list){List<String> rows=new ArrayList<>();for(Object row:list)rows.add(json(row));return "["+String.join(",",rows)+"]";}
        throw new Unverified("protocol_unverified");
    }
    public static void main(String[] args){
        boolean complete=false;String reason="protocol_unverified",data="null";int code=0;
        try {
            require(args.length>0 && (Set.of("linkage","providers").contains(args[0]) || args.length==1));
            switch(args[0]){
                case "idle" -> {Thread.sleep(600000);return;}
                case "identity" -> data=json(identity());
                case "features" -> data=featureJson(AppGuardRuntimeProbe.evaluate(true));
                case "tree" -> {Map<String,String> os=osRelease();data=json(tree(ROOT,os.get("ID"),os.get("VERSION_ID"),10001));}
                case "database-hashes" -> data=json(databases());
                case "rpm" -> {String rows=packages(null);data=json(Map.of("rows",rows,"count",rows.lines().count()));}
                case "linkage" -> data=json(linkage(args));
                case "providers" -> data=json(providers(args));
                default -> throw new Unverified("protocol_unverified");
            }
            complete=true;reason="measured";
        }catch(Unverified error){reason=error.reason;}
        catch(NoSuchFileException|AccessDeniedException error){reason="read_unavailable";}
        catch(InterruptedException error){reason="cancelled";Thread.currentThread().interrupt();}
        catch(IOException error){reason="read_unavailable";}
        catch(Exception error){reason="protocol_unverified";}
        catch(Throwable error){reason="resource_unverified";}
        String output="{\"schema\":1,\"complete\":"+complete+",\"reason\":\""+reason+"\",\"data\":"+data+"}";
        if(output.getBytes(StandardCharsets.UTF_8).length>MAX)output="{\"schema\":1,\"complete\":false,\"reason\":\"output_limit\",\"data\":null}";
        System.out.println(output);if(args.length!=1 && !(args.length>0 && Set.of("linkage","providers").contains(args[0])))code=2;
        System.exit(code);
    }
}
