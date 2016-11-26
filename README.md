ReadMe.txt
Instructions 

For Execution File 


1. Run "make" with .c files to generate executbles for "server" and "client"
	a. For Individual Files run make server or make client
	b. For removal of object files Run "make clean"

2. To Find the IP of server run "ifconfig" on sever or use "localhost" in place of IP for local machines
	a. Server side 
		Run "./server <Port Number>" .(Use port Numbers > 5000 .)
	b. Client side
		Run "./client <Server IP> <Port No>".(Make use of same port as used for server)	

Available Commands:

1. get <file_name> 
	a.Transfers a  file from server to client .
	b.Displays "File Not Present" on client console if not available on server side 
	
2. put <file_name> 
	a.Transfers a  file from client to server .
	b.Displays "<filename>: No such file or directory" on client console if not available 
	c.Displays "Error" on server console if not available 

***Above commands also display following information at end of execution

	"Rcvxd packet: total Bytes <packet value>:<Total bytes of File Transferred>"
	"Files Recieved match with Server" 	- if MD5 of <file_name> matches between the Server and Client 
	<or> 
	"Retry ,Files dont match!!" - if MD5 of <file_name> did not match between the Server and Client 

3.ls
	a.Displays the list of files present in current directory of server on client console seperated by tab space

4.exit
	a. Exits server and client 

5.For other commands
	Displays "Command not supported"


Assumptions 
1.Server is up before starting the client - Used in Blocking mode for comands 
	and unblocking for packet data

2.Client does not support file_name with spaces

3.A single space between get/put command and <file_name> - Parsing is sepcific to spaces



Functionality

1.MD5 Implementation and transmission 
 	a.After transmission of File/Image/video data from sender to reciever a MD5 hash from sender of file is send to reciever . Similarly a MD5 has value is calculated at reciever end to compare them  
 	
 	"Rcvxd packet: total Bytes <packet value>:<Total bytes of File Transferred>"
	
	"Files Recieved match with Server" 	- if MD5 of <file_name> matches between the Server and Client 
	<or> 
	"Retry ,Files dont match!!" - if MD5 of <file_name> did not match between the Server and Client 


	b.Implementation Reliability 
		(i)#define RELIABILITY --keep it defined in server and client for RELIABILITY implementation. 
		"RELIABILITY Incoporated" on client and server will be displayed if this is "ON"  

		(ii)Each packet from sender side is attached a header of packet no and packet size along
			with data of file . This is send to receiver with a wait for acknowldgement on sender side.

		(iii)The receiver acknowledges  sender with "ACK<packet_no>". This packet no is matched with send <packet_no>. 

		(iv)If it does not match or not received within time of SOCKET(SO_RCVTIMEO) timeout The Packet is retransmitted from sender to receiver for MAXREPEATCOUNT  times

		(v) If ACK is missed is transmission . The prev_packet_no helps to determine if new packet is duplicate or not at receiver side 

	c. I have tried put and get commands with video(.mp4) and pdf files of >100MB. 
		It does succeed in transmission even with CSEL servers ,sometimes barring the first attempt	


3.
	#undefine NONBLOCKING -- Keep it undefined
	This functionality is not implemented correctly .As during NONBLOCKING mode commands are not recieved correctly .Therefore, for data packet transmission the Socket_RCV is set a timeout and after completion of all file transmission timeout is {0,0} to resume blocking mode



