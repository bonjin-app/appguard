package io.appguard.example;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.util.*;

/** Optional owner-only process-local snapshots, without crash durability. No HTTP metrics endpoint or request data. */
final class BackendCounters {
    private final Path file;
    private final Map<String,Long> values=new LinkedHashMap<>();
    BackendCounters(Path file)throws IOException {
        this.file=file;for(String name:List.of("dispatch","auth","key","replay","resource"))values.put(name,0L);
        if(file!=null){
            Set<PosixFilePermission> permissions=Files.getPosixFilePermissions(file,LinkOption.NOFOLLOW_LINKS);
            if(!permissions.equals(Set.of(PosixFilePermission.OWNER_READ,PosixFilePermission.OWNER_WRITE)) || Files.size(file)!=0)throw new IllegalArgumentException("New owner-only counter file required");
            write();
        }
    }
    synchronized void increment(String name){
        if(!values.containsKey(name))throw new IllegalArgumentException("Unknown counter");
        values.put(name,Math.incrementExact(values.get(name)));
        try{write();}catch(IOException e){throw new IllegalStateException("Counter snapshot unavailable");}
    }
    synchronized Map<String,Long> snapshot(){return Map.copyOf(values);}
    private void write()throws IOException {
        if(file==null)return;
        StringJoiner json=new StringJoiner(",","{","}\n");values.forEach((name,value)->json.add("\""+name+"\":"+value));
        try(FileChannel channel=FileChannel.open(file,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS)){
            // Process-local measurement only: closing publishes the completed write
            // to readers without serializing requests on forced disk durability.
            channel.truncate(0);ByteBuffer data=StandardCharsets.US_ASCII.encode(json.toString());while(data.hasRemaining())channel.write(data);
        }
    }
}
