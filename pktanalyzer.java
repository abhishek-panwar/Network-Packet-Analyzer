import java.io.FileInputStream;
import java.io.IOException;

public class pktanalyzer {

	public static void main(String[] args) throws IOException {
		
		String fileName = args[0];
		readFile(fileName);
	}
	
	public static void readFile(String fileName) throws IOException
	{
		FileInputStream reader = new FileInputStream(fileName);
		//reads the file data in buffer with whatever length available
		byte[] buffer = new byte[reader.available()];
		reader.read(buffer);
		
		printEthernetHeader(buffer);
		printIPHeader(buffer);
		if(getProtocolType(buffer).equals("TCP"))
			printTCPHeader(buffer);
		else if(getProtocolType(buffer).equals("UDP"))
			printUDPHeader(buffer);
		else if(getProtocolType(buffer).equals("ICMP"))
			printICMPHeader(buffer);
	}
	
	
	public static void printEthernetHeader(byte[] buffer)
	{//Ethernet header is of starting 14 bytes
		byte[] destination = new byte[6];
		byte[] source = new byte[6];
		
		for(int i=0;i<6;i++)
			destination[i] = buffer[i];
		for(int i=6;i<12;i++)
			source[i-6] = buffer[i];
		//concatenate the values of bytes in hexa format
		String type = String.format("%02X", buffer[12])+""+String.format("%02X", buffer[13]);
		
		System.out.println("ETHER: ----- Ether Header -----");
		System.out.println("ETHER:");
		System.out.println("ETHER: Packet size = "+buffer.length+" bytes");
		System.out.print("ETHER: Destination = ");
		printMacAddress(destination);
		System.out.print("ETHER: Source      = ");
		printMacAddress(source);
		if(type.equals("0800")) System.out.println("ETHER: Ethertype = 0800 (IP)");
		System.out.println("ETHER:");
	}
	
	public static void printIPHeader(byte[] buffer)
	{//IP header is from 14 to 34 byte
		System.out.println("IP: ----- IP Header -----");
		System.out.println("IP:");
		//print second half of a byte
		int version = Integer.parseInt(String.format("%02X ", buffer[14]).substring(0, 1));
		System.out.println("IP: Version = "+version);
		
		int headerLength = Integer.parseInt(String.format("%02X ", buffer[14]).substring(1, 2))*4;
		
		System.out.println("IP: Header length = "+headerLength+" bytes");
		
		String typeOfService = String.format("%02X ", buffer[15]);
		System.out.println("IP: Type of service = 0x"+typeOfService);
		printIPTypeOfServiceAttributes(buffer);
		//merges two bytes. left shift 1st byte to 8 places in order to make room for 2nd byte
		//then OR the 2nd byte 
		System.out.println("IP: Total length = "+(buffer[16]<<8 | buffer[17]&0xff)+" bytes");
		System.out.println("IP: Identification = "+((buffer[18]<<8 | buffer[19]&0xff)&0xffff));
		String flag = String.format("%02X ", buffer[20]).substring(0, 1);
		
		System.out.println("IP: Flags = 0x"+flag);
		
		printIPFlagsAttributes(buffer);
		
		System.out.println("IP: Fragment offset = "+(buffer[20]&15<<8 | buffer[21]&0xff)+" bytes");
		System.out.println("IP: Time to live = "+(buffer[22]&0xff)+" seconds/hops");
		
		int protocol = buffer[23];
		if(protocol==1) System.out.println("IP: Protocol = "+protocol+" (ICMP)");
		else if(protocol==6) System.out.println("IP: Protocol = "+protocol+" (TCP)");
		else if(protocol==17) System.out.println("IP: Protocol = "+protocol+" (UDP)");

		System.out.println("IP: Header checksum = 0x"+String.format("%02X",buffer[24])+ String.format("%02X",buffer[25]&0xff));
		
		byte[] sourceAddress = new byte[4];
		byte[] destinationAddress = new byte[4];
		
		for(int i=26;i<=29;i++)
			sourceAddress[i-26]=buffer[i];
		for(int i=30;i<=33;i++)
			destinationAddress[i-30]=buffer[i];
		System.out.print("IP: Source address = ");
		printIPAddress(sourceAddress);
		System.out.print("IP: Destination address = ");
		printIPAddress(destinationAddress);
		System.out.println("IP: No options");
		System.out.println("IP:");

	}
	
	public static void printIPFlagsAttributes(byte[] buffer)
	{
		if((buffer[20]&1<<6)==0) System.out.println("IP:       .0.. .... = OK to fragment");
		else System.out.println("IP:       .1.. .... = do not fragment");
		
		if((buffer[20]&1<<5)==0) System.out.println("IP:       ..0. .... = last fragment");
		else System.out.println("IP:       ..1. .... = more fragments");
	}
	
	public static void printIPTypeOfServiceAttributes(byte[] buffer)
	{	//taking left 5 bits
		System.out.println("IP:       xxx. .... = "+(buffer[15]>>5)+" (precedence)");
		
		if((buffer[15]&1<<4) ==0) System.out.println("IP:       ...0 .... = normal delay");
		else System.out.println("IP:       ...1 .... = low delay");
		
		if((buffer[15]&1<<3) ==0) System.out.println("IP:       .... 0... = normal throughput");
		else System.out.println("IP:       .... 1... = high throughput");
			
		if((buffer[15]&1<<2) ==0) System.out.println("IP:       .... .0.. = normal reliability");
		else System.out.println("IP:       .... .1.. = high reliability");
	}
	
	public static String getProtocolType(byte[] buffer)
	{
		int protocol = buffer[23];
		if(protocol==1) return "ICMP";
		if(protocol==6) return "TCP";
		if(protocol==17) return "UDP";
		return "";
	}
	
	public static void printTCPHeader(byte[] buffer)
	{
		System.out.println("TCP: ----- TCP Header -----");
		System.out.println("TCP:");
		System.out.println("TCP: Source port = "+((buffer[34]<<8 | buffer[35]&0xff)&0xFFFF));
		System.out.println("TCP: Destination port = "+((buffer[36]<<8 | buffer[37]&0xff)&0xFFFF));
		System.out.println("TCP: Destination port = "+((buffer[38]<<24 | buffer[39]<<16 | buffer[40]<<8 | buffer[41]&0xff)&0xFFFFFFFF));
		
		System.out.println("TCP: Acknowledgement number = "+Long.valueOf(String.format("%02x", buffer[42])+
																			String.format("%02x", buffer[43])+
																				String.format("%02x", buffer[44])+
																					String.format("%02x", buffer[45]), 16));
		System.out.println("TCP: Data offset = "+String.format("%02X ", buffer[46]).substring(0, 1)+" bytes");
		
		System.out.println("TCP: Flags = 0x"+String.format("%02x", (buffer[47]&63)));
		printTCPFlagAttributes(buffer);
		
		System.out.println("TCP: Window = "+((buffer[48]<<8 | buffer[49]&0xff)&0xFFFF));
		System.out.println("TCP: Checksum = 0x"+String.format("%02x", buffer[50])+String.format("%02x", buffer[51]));
		System.out.println("TCP: Urgent pointer = "+((buffer[52]<<8 | buffer[53]&0xff)&0xFFFF));
		System.out.println("TCP: No options");
		System.out.println("TCP:");
		System.out.println("TCP: Data: (first 64 bytes)");
		
		for(int i=0;i<4;i++)
		{
			System.out.print("TCP: ");
			for(int j=0;j<16;j++)
			{
				System.out.print(String.format("%02x", buffer[34+i*16+j]));
				if(j%2!=0)
					System.out.print(" ");
			}
			System.out.print("\t'");
			for(int j=0;j<16;j++)
			{
				
				int ch = buffer[34+i*16+j];
				if(ch>32 && ch<=127)
					System.out.print((char)buffer[34+i*16+j]);
				else
					System.out.print('.');
			}
			System.out.println("'");
		}
	}
	
	public static void printUDPHeader(byte[] buffer)
	{
		System.out.println("UDP: ----- UDP Header -----");
		System.out.println("UDP:");
		System.out.println("UDP: Source port = "+((buffer[34]<<8 | buffer[35]&0xff)&0xffff));
		System.out.println("UDP: Destination port = "+((buffer[36]<<8 | buffer[37]&0xff)&0xffff));
		int length = (buffer[38]<<8 | buffer[39]&0xff)&0xffff;
		System.out.println("UDP: Length = "+length);
		System.out.println("UDP: Checksum = 0x"+(String.format("%02x", buffer[40]) + String.format("%02x", buffer[41])));
		System.out.println("UDP:");
		System.out.println("UDP: Data: (first 64 bytes)");
		
		for(int i=0;i<length/16+1;i++)
		{
			System.out.print("UDP: ");
			for(int j=0;j<16;j++)
			{
				if(34+i*16+j>=34+length) break;
				System.out.print(String.format("%02x", buffer[34+i*16+j]));
				if(j%2!=0)
					System.out.print(" ");
			}
			
			if(i==length/16)System.out.print("\t\t\t'");
			else System.out.print("\t'");
			for(int j=0;j<16;j++)
			{
				if(34+i*16+j>=34+length) break;
				int ch = buffer[34+i*16+j];
				if(ch>32 && ch<=127)
					System.out.print((char)buffer[34+i*16+j]);
				else
					System.out.print('.');
			}
			System.out.println("'");
		}
	}
	
	public static void printICMPHeader(byte[] buffer)
	{
		System.out.println("ICMP: ----- ICMP Header -----");
		System.out.println("ICMP:");
		int type = buffer[34];
		switch(type)
		{
		case 0: System.out.println("ICMP: Type = "+type+" (Echo reply)");break;
		case 3: System.out.println("ICMP: Type = "+type+" (Network unreachable)");break;
		case 4: System.out.println("ICMP: Type = "+type+" (Source quench)");break;
		case 5: System.out.println("ICMP: Type = "+type+" (Redirect for Network)");break;
		case 8: System.out.println("ICMP: Type = "+type+" (Echo request)");break;
		case 9: System.out.println("ICMP: Type = "+type+" (Router advertisement)");break;
		case 10: System.out.println("ICMP: Type = "+type+" (Route selection)");break;
		case 11: System.out.println("ICMP: Type = "+type+" (TTL equals 0 during transit)");break;
		case 12: System.out.println("ICMP: Type = "+type+" (IP header bad (catchall error))");break;
		case 13: System.out.println("ICMP: Type = "+type+" (Timestamp request (obsolete))");break;
		case 14: System.out.println("ICMP: Type = "+type+" (Timestamp reply (obsolete))");break;
		case 15: System.out.println("ICMP: Type = "+type+" (Information request (obsolete))");break;
		case 16: System.out.println("ICMP: Type = "+type+" (Information reply (obsolete))");break;
		case 17: System.out.println("ICMP: Type = "+type+" (Address mask request)");break;
		case 18: System.out.println("ICMP: Type = "+type+" (Address mask reply)");break;
		default: System.out.println("ICMP: Type = "+type+" (Other)");break;
		}
		System.out.println("ICMP: Code = "+buffer[35]);
		System.out.println("ICMP: Checksum = 0x"+String.format("%02x", buffer[36])+String.format("%02x", buffer[37]));
		System.out.println("ICMP:");
	}
	
	public static void printTCPFlagAttributes(byte[] buffer)
	{
		if((buffer[47]&1<<5)==0) System.out.println("TCP:      ..0. .... = No urgent pointer");
		else System.out.println("TCP:      ..1. .... = Urgent pointer");
		
		if((buffer[47]&1<<4)!=0) System.out.println("TCP:      ...1 .... = Acknowledgement");
		else System.out.println("TCP:      ...0 .... = No Acknowledgement");
		
		if((buffer[47]&1<<3)!=0) System.out.println("TCP:      .... 1... = Push");
		else System.out.println("TCP:      .... 0... = No Push");
		
		if((buffer[47]&1<<2)==0) System.out.println("TCP:      .... .0.. = No reset");
		else System.out.println("TCP:      .... .1.. = Reset");
		
		if((buffer[47]&1<<1)==0) System.out.println("TCP:      .... ..0. = No Syn");
		else System.out.println("TCP:      .... ..1. = Syn");
		
		if((buffer[47]&1)==0) System.out.println("TCP:      .... ...0 = No Fin");
		else System.out.println("TCP:      .... ...1 = Fin");
	}
	
	public static void printMacAddress(byte[] arr)
	{
		for(int i=0;i<arr.length-1;i++)
			System.out.print(String.format("%02X", arr[i])+":");
		System.out.print(String.format("%02X ", arr[arr.length-1])+"");
		System.out.println();
	}
	
	public static void printIPAddress(byte[] arr)
	{
		for(int i=0;i<arr.length-1;i++)
			System.out.print((arr[i]&0xFF)+".");
		System.out.print((arr[arr.length-1]&0xFF)+"");
		System.out.println();
	}
}
