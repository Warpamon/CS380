import java.io.BufferedReader;
import java.nio.ByteBuffer;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.util.Arrays;

public class Ipv4 {

	public static void main(String[] args) {
		 Ipv4 ipv4 = new Ipv4();
	        try {
	            Socket socket = new Socket("codebank.xyz", 38003);
	            BufferedReader br = new BufferedReader(new InputStreamReader(socket.getInputStream()));
	 
	            // Header fields
	            short versHlenTos = 0x4500;
	            short len;
	            short ident = 0;
	            short flagOff = 0x4000; // no fragmentation
	            byte ttl = 50;
	            byte protocol = 6; // TCP
	            short checksum;// header only
	            int sourAdd = 0; // IP address of my choice
	            byte[] destAdd = socket.getInetAddress().getAddress();
	            byte[] data = null;

	 
	            int dataSize = 2;
	            for (int i = 0; i < 12; ++i) {
	                System.out.println("Data Length:" + dataSize);
	                data = ipv4.fillDat(dataSize);
	 
	                len = (short) (20 + dataSize);	 
	       
	                checksum = 0;
	                ByteBuffer bbuf = ByteBuffer.allocate(20 + dataSize);
	                bbuf.putShort(versHlenTos);
	                bbuf.putShort(len);
	                bbuf.putShort(ident);
	                bbuf.putShort(flagOff);
	                bbuf.put(ttl);
	                bbuf.put(protocol);
	                bbuf.putShort(checksum);
	                bbuf.putInt(sourAdd);
	                bbuf.put(destAdd);
	                bbuf.put(data);
	 
	                checksum = ipv4.checksum(bbuf.array());
	 
	                // Create Packet
	                bbuf.clear();
	                bbuf.putShort(versHlenTos);
	                bbuf.putShort(len);
	                bbuf.putShort(ident);
	                bbuf.putShort(flagOff);
	                bbuf.put(ttl);
	                bbuf.put(protocol);
	                bbuf.putShort(checksum);
	                bbuf.putInt(sourAdd);
	                bbuf.put(destAdd);
	                bbuf.put(data);
	                dataSize = dataSize * 2;
	 
	                socket.getOutputStream().write(bbuf.array());
	                System.out.println(br.readLine() + "\n");
	            }
	 
	            socket.close();
	        } catch (IOException e) {
	            e.printStackTrace();
	        }
	}
	public byte[] fillDat(int dataSize) {
		 
        byte[] data = new byte[dataSize];
 
        for (int i = 0; i < dataSize; i++) {
            data[i] = 0;
        }
 
        return data;
    }
	
	public short checksum(byte[] b) {
        int sum = 0;
        int length = b.length;
        int i = 0;
 
        while (length > 1) {
            int s = ((b[i++] << 8) & 0xFF00) | (b[i++] & 0x00FF);
            sum += s;
            if ((sum & 0xFFFF0000) > 0) {
                sum &= 0xFFFF;
                sum++;
            }
            length -= 2;
        }
 
        return (short) ~(sum & 0xFFFF);
    }

}
