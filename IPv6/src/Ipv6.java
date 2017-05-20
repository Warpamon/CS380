import java.io.BufferedReader;
import java.nio.ByteBuffer;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.util.Arrays;

public class Ipv6 {

	public static void main(String[] args) {
		Ipv6 pack = new Ipv6();
		try {
            Socket socket = new Socket("codebank.xyz", 38004);
            BufferedReader br = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            
            //IPv6 header fields
            short verTraf = 0x6000;//version and traffic
            short flow = 0;//flow label not imp
            short payLen;//Length of data after header
            byte nHeader = 17;//UDP
            byte hopL = 20;//hop limit
            //IPv4 extension to make into IPv6 = 0:0:0:0:0:FFFF:dest:addr
            //so when its stored into a byte array = 10 zeros and FF converts to -1 in java
            byte[] dest = new byte[]{0,0,0,0,0,0,0,0,0,0,-1,-1};
            //my Ipv4 address at home convert to Ipv6
            byte[] sourceA = new byte[] {0,0,0,0,0,0,0,0,0,0,-1,-1,-118,-27,-108,12};
            //Ipv4 destination address
            byte[] dest4 = socket.getInetAddress().getAddress();
            //extending IPv4 to IPv6 adress
            byte[] dest6 = new byte[dest.length + dest4.length];
            System.arraycopy(dest, 0, dest6, 0, dest.length);
            System.arraycopy(dest4, 0, dest6, dest.length, dest4.length);
            byte[] data = null;
            // Ignoring Options/Pad
            System.out.println("Couldnt find a way to properly convert this decimal values to Hex trough"
            		+ "\n java since it considers them signed values. But when converted"
            		+ "\n 202 = CA, 254 = FE, 186 = BA, 190 = BE.\n");
            int dataSize = 2;
            for (int i = 0; i < 12; ++i) {
                System.out.println("Data Length:" + dataSize);
                data = pack.fillD(dataSize);
 
                payLen = (short) (dataSize); // header+data

                ByteBuffer bbuf = ByteBuffer.allocate(40 + dataSize);

                bbuf.putShort(verTraf);
                bbuf.putShort(flow);
                bbuf.putShort(payLen);
                bbuf.put(nHeader);
                bbuf.put(hopL);
                bbuf.put(sourceA);
                bbuf.put(dest6);
                bbuf.put(data);
                dataSize = dataSize * 2;
 
                socket.getOutputStream().write(bbuf.array());

                System.out.print("Response: ");
                int code = br.read();
                int code1 = br.read();
                int code2 = br.read();
                int code3 = br.read();
                System.out.print(code + ","+ code1 + ","+code2 + ","+ code3 );
                System.out.println( "\n");
            }
 
            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

	}
	public byte[] fillD(int dataSize) {
		 
        byte[] data = new byte[dataSize];
 
        for (int i = 0; i < dataSize; i++) {
            data[i] = 0;
        }
 
        return data;
    }

}
