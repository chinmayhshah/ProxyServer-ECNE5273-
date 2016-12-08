/*******************************************************************************
Web Server implementation 
Author :Chinmay Shah 
File :server.c
Last Edit : 10/10
******************************************************************************/

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include <dirent.h>
#include <openssl/md5.h>
#include <sys/time.h>
#include <pthread.h> // For threading , require change in Makefile -lpthread
//#include <time.h>

/* You will have to modify the program below */
#define LISTENQ 2000 
#define SERV_PORT 3000

#define MAXCOLSIZE 100
#define HTTPREQ 	30


#define MAXBUFSIZE 600000
#define MAXPACKSIZE 10000
#define ERRORMSGSIZE 10000
#define MAXCOMMANDSIZE 1000
#define MAXCONTENTSUPPORT 15
#define MAXMD5LENGTH 33
	
#define MAX_TIME_OUT 300.0 //in seconds

//#define DEBUGLEVEL
#define MAXCACHESIZE 1000

#ifdef DEBUGLEVEL
	#define DEBUG 1
#else
	#define	DEBUG 0
#endif

#define DEBUG_PRINT(fmt, args...) \
        do { if (DEBUG) fprintf(stderr, "\n %s:%d:%s(): " fmt, __FILE__, \
                                __LINE__, __FUNCTION__, ##args); } while (0)





typedef char type2D[10][MAXCOMMANDSIZE];

typedef enum HTTPFORMAT{
							HttpExtra,//Extra Character
							HttpMethod,//Resource Method
							HttpURL,// Resource URL
							HttpVersion //Resource Version 
						}HTTP_FM;// Resource format

//HTTP Mehthod supported 
typedef enum HTTPMETHOD{
							HTTP_GET,//GET
							HTTP_POST

						}HTTP_METHOD;

//For configuration File

typedef enum CONFIGFORMAT{
							FmtExtra,//Format Extra Character
							ConfigType,//Config Type 
							ConfigContent,//Config Content
							ConfigFileType//Config File type 
						}CONFIG_FM;// Config File format


struct ConfigData{
		char listen_port[MAXCOLSIZE];
		char document_root[MAXCOLSIZE];
		char directory_index[MAXCOLSIZE];
		char content_type[MAXCONTENTSUPPORT][MAXCOLSIZE];
		char response_type[MAXCONTENTSUPPORT][MAXCOLSIZE];
		char keep_alive_time[MAXCOLSIZE];
};



struct HttpFormats_struct{
		char HttpMethodVaue[MAXCOLSIZE];//Resource Method
		char HttpURLValue[MAXCOLSIZE];// Resource URL
		char HttpVersionValue[MAXCOLSIZE]; //Resource Version 
		int port;
};


//chaching , hash table
struct cacheContent 
{
	char url[MAXCOLSIZE];
	char hashValue[MAXCOLSIZE];
	time_t expirytime;

};





typedef enum ErrorCodes{
		STATUS_OK,
		STATUS_ERROR,
		STATUS_ERROR_FILE_NOT_FOUND,
		STATUS_ERROR_SOCKET_NOT_WRITTEN,
		STATUS_ERROR_REQUEST,
		STATUS_ERROR_TIME
		
}ErrorCodes_TypeDef;


struct ConfigData config;
int maxtypesupported=0;
//typedef enum HTTPFORMAT{RM,RU,RV}HTTP_FM;


int server_sock,client_sock;                           //This will be our socket
struct sockaddr_in server, client,ProxyClient;     //"Internet socket address structure"
unsigned int remote_length;         //length of the sockaddr_in structure
int nbytes;                        //number of bytes we receive in our message


//Time set for Time out 
struct timeval timeout={0,100000};     

//fixed Root , take from configuration file 
//char * ROOT = "/home/chinmay/Desktop/5273/PA2/www";
char *configfilename ="ws.conf";


//Using Mutex
pthread_mutex_t thread_mutex;

/*******************************************************************************************
//Parse a configutation file 
//
I/p : File name 

Checks : 
		1) Config File present or not
		2) Discard Commented out lines "#"
		3) Discard Blank Lines
		4) Start with a blank
 	  
o/p : Structure of data for configuration file 

Basic Start refernece for coding 
https://www.pacificsimplicity.ca/blog/simple-read-configuration-file-struct-example

Format :
*********************************************************************************************/
int config_parse(char Filename[MAXCOLSIZE]){

	int i=0 ;
	FILE *filepointer;
	ssize_t read_bytes,length;
	//struct ConfigData config;
	char readline[MAXBUFSIZE];
	char (*split_attr)[MAXCOLSIZE];
	char tempcopy[MAXCOLSIZE];
	int content_location=0,total_attr_commands=0;
	
	DEBUG_PRINT("In");
	//Read File 
	//FILE *filetoread = fopen(Filename,"r");
	if ((filepointer=fopen(Filename,"r"))==NULL){//if File  not found 
			printf("Configuration file not found Try Again \n");
			//perror("File not Found");
			exit(-1);
		}
	else
	{
		while((fgets(readline,sizeof(readline),filepointer))!=NULL){			

			readline[strlen(readline)-1] = '\0';
			//check for comments 			
			if (readline[0]=='#'){
				DEBUG_PRINT("comment");
			}
			else if (!strcmp(readline,"\n\r")){
				DEBUG_PRINT("Blank Line ");
			}	
			else
			{
				DEBUG_PRINT("%s\n",readline);	
				//parse and store file 

				if ((split_attr=malloc(sizeof(split_attr)*MAXCOLSIZE))){	
					total_attr_commands=0;
					if((total_attr_commands=splitString(readline," ",split_attr,4))<0)
					{
						DEBUG_PRINT("Error in Split \n\r");
						
					}
					else
					{
						DEBUG_PRINT("%d",total_attr_commands);
						DEBUG_PRINT("Config Type %s",split_attr[ConfigType]);
						//split_attr[ConfigFileType][sizeof(ConfigType)]='\0';
						length=strlen(split_attr[ConfigType]);
	
						//strncpy(tempcopy,split_attr[ConfigType],length);
						//DEBUG_PRINT("Copied%s",tempcopy);
						//Check for Listen Port 			
						if(split_attr[ConfigType]!=NULL)
						{
							////Check for Listen Port 
							if(!(strncmp(split_attr[ConfigType],"ListenPort",length))){							
								
								bzero(config.listen_port,sizeof(config.document_root));
								strcpy(config.listen_port,split_attr[ConfigContent]);
								DEBUG_PRINT("Found Listen Port %s %s",split_attr[ConfigContent],config.listen_port);
							}
							else
							{
								DEBUG_PRINT("Listen Port not found ");
							}
														
							////Check for Document Root
							if(!(strncmp(split_attr[ConfigType],"DocumentRoot",length))){
					
								bzero(config.document_root,sizeof(config.document_root));
								strcpy(config.document_root,split_attr[ConfigContent]);
								DEBUG_PRINT("Found DocumentRoot %s %s",split_attr[ConfigContent],config.document_root);
							}
							else
							{
								DEBUG_PRINT("DocumentRoot not found ");
							}

							////Check for Document Index
							if(!(strncmp(split_attr[ConfigType],"DirectoryIndex",length))){

								
								//);
								bzero(config.directory_index,sizeof(config.directory_index));
								strcpy(config.directory_index,split_attr[ConfigContent]);
								DEBUG_PRINT("Found DirectoryIndex %s %s",split_attr[ConfigContent],config.directory_index);
							}
							else
							{
								DEBUG_PRINT("DirectoryIndex not found ");
							}


							////Check for ContentType Index
							if(!(strncmp(split_attr[ConfigType],"ContentType",length))){										
								bzero(config.content_type[content_location],sizeof(config.content_type[content_location]));
								bzero(config.response_type[content_location],sizeof(config.response_type[content_location]));
								strcpy(config.content_type[content_location],split_attr[ConfigContent]);
								strncpy(config.response_type[content_location],split_attr[ConfigFileType],sizeof(config.response_type[content_location]));
								content_location ++;
								DEBUG_PRINT("Found ContentType %s %s %d",split_attr[ConfigContent],split_attr[ConfigFileType],content_location);
								DEBUG_PRINT("Stored ContentType %s %s %d",split_attr[ConfigContent],split_attr[ConfigFileType],content_location);
							}
							else
							{
								DEBUG_PRINT("ContentType not found ");
							}

							////Check for KeepaliveTime
							if(!(strncmp(split_attr[ConfigType],"KeepaliveTime",length))){											
								bzero(config.keep_alive_time,sizeof(config.keep_alive_time));
								strcpy(config.keep_alive_time,split_attr[ConfigContent]);
								DEBUG_PRINT("Found KeepaliveTime %s ",config.keep_alive_time);
								
							}
							else
							{
								DEBUG_PRINT("KeepaliveTime not found ");
							}
						}
					}	
					
				}
				else
				{
					DEBUG_PRINT("Cant Allocate Memory");
				}	
			}
			
		}	
		if (split_attr!=NULL){


			//free alloaction of memory 
			for(i=0;i<total_attr_commands;i++){
				free((*split_attr)[i]);
			}
			free(split_attr);//clear  the request recieved 

		}
		else{

			DEBUG_PRINT("Configuration Details could not be found ");

		}
		DEBUG_PRINT("AFter reading File ");
		fclose (filepointer);
		DEBUG_PRINT("Close File Pointer");
	}

	return (content_location);//return total content type 

}


/*************************************************************
//Split string on basis of delimiter 
//Assumtion is string is ended by a null character
I/p : splitip - Input string to be parsed 
	  delimiter - delimiter used for parsing 
o/p : splitop - Parsed 2 D array of strings
	  return number of strings parsed 

Referred as previous code limits number of strings parsed 	  
http://stackoverflow.com/questions/20174965/split-a-string-and-store-into-an-array-of-strings
**************************************************************/
int splitString(char *splitip,char *delimiter,char (*splitop)[MAXCOLSIZE],int maxattr)
{
	int sizeofip=1,i=1;
	char *p=NULL;//token
	char *temp_str = NULL;


	DEBUG_PRINT("value split %d",sizeofip);
	
	if(splitip==NULL || delimiter==NULL){
		printf("Error\n");
		return -1;//return -1 on error 
	}
	
	
	p=strtok(splitip,delimiter);//first token string 
	
	//Check other token
	while(p!=NULL && p!='\n' && sizeofip<maxattr )
	{
		
		
		temp_str = realloc(*splitop,sizeof(char *)*(sizeofip +1));
		
		if(temp_str == NULL){//if reallocation failed	

			
			//as previous failed , need to free already allocated 
			if(*splitop !=NULL ){
				for (i=0;i<sizeofip;i++)
					free(splitop[i]);
				free(*splitop);	
			}

			return -1;//return -1 on error 
		}
		
		
		//Token Used
		strcat(p,"\0");
		// Set the split o/p pointer 
		//splitop[0] = temp_str;

		//allocate size of each string 
		//copy the token tp each string 
		//bzero(splitop[sizeofip],strlen(p));
		memset(splitop[sizeofip],0,sizeof(splitop[sizeofip]));
		strncpy(splitop[sizeofip],p,strlen(p));
		strcat(splitop[sizeofip],"\0");
		DEBUG_PRINT	("%d : %s",sizeofip,splitop[sizeofip]);
		sizeofip++;

		//get next token 
		p=strtok(NULL,delimiter);
		
	}

	
	//if (sizeofip<maxattr || sizeofip>maxattr){
	if (sizeofip>maxattr+1){
		DEBUG_PRINT("unsuccessful split %d %d",sizeofip,maxattr);
		return -1;
	}	
	else
	{	
		//DEBUG_PRINT("successful split %d %d",sizeofip,maxattr);
		return sizeofip;//Done split and return successful }
	}	
		

	return sizeofip;	

	
}

int error_response(char *err_message,char Http_URL[MAXCOLSIZE],int sock,char Http_Version[MAXCOLSIZE],char reason[MAXCOLSIZE]){

	char error_message[ERRORMSGSIZE];
	
	//write(sock,"Check data",strlen("Check data\n"));
	bzero(error_message,strlen(error_message));
	
	DEBUG_PRINT("%s",err_message);
	
	sprintf(error_message,"%s %s\r<html>\n\n<head>\r\n<title>%s</title>\n\r</head>\n\r<body>\n\r<h1>%s</h1>\n\r<b>Reason :</b>	<font color=\"red\"> %s :<font color=\"blue\">%s\n\r</body>\n\r</html>\n\r",Http_Version, err_message,err_message,err_message,reason,Http_URL);
	
	DEBUG_PRINT("%s",error_message);
	
	write(sock,error_message,strlen(error_message));
	
	return 0;
}



ErrorCodes_TypeDef MD5String (char *inputString,char *retMD5)
{
	
	char runcommand[MAXCOLSIZE];
	//char path[1035];
	FILE *fp;	
	char retval[MAXMD5LENGTH+10];
	//char tempval[MAXMD5LENGTH];
	DEBUG_PRINT("Input string for MD5SUM %s",inputString);

	bzero(retMD5,sizeof(retMD5));
	//pthread_mutex_lock(&thread_mutex);//lock mutex	
	//clear the buffers
	bzero(runcommand,sizeof(runcommand));
	bzero(retval,sizeof(retval));
	sprintf(runcommand,"echo %s|md5sum",inputString);
	//	system(syscommand);
	
	DEBUG_PRINT("sys command %s",runcommand);
    /* Open the command for reading. */
    fp = popen(runcommand, "r");
    printf("\n");
    if (fp == NULL) {
     	DEBUG_PRINT("Failed to run command\n" );
     	return STATUS_ERROR;
  	}

  /* Read the output a line at a time - output it. */
  while (fgets(retval, sizeof(retval)-1, fp) != NULL) {
    printf("Return value %s\n", retval);
    //strcpy(returnString,path);
  }

  /* close */
  pclose(fp);
  
  strncpy(retMD5,retval,(MAXMD5LENGTH));
  //pthread_mutex_unlock(&thread_mutex);//lock mutex	
  //tempval[33]='\0';
  printf("Temp val %s \n",retMD5);

  return STATUS_OK;


}




/*************************************************************************************
Calculate MD5 and return value as string 
Assumtion : File is in same directory 
i/p - Filename
o/p - MD5 Hash value 
Ref for understanding :http://stackoverflow.com/questions/10324611/how-to-calculate-the-md5-hash-of-a-large-file-in-c?newreg=957f1b2b2132420fb1b4783484823624
Library :http://stackoverflow.com/questions/14295980/md5-reference-error
		gcc client.c -o client -lcrypto -lssl

***************************************************************************************/
ErrorCodes_TypeDef MD5Cal(char *path, char *buff)
{
	//unsigned char *MD5_gen;
	unsigned char md5sum[MD5_DIGEST_LENGTH];
	MD5_CTX mdCont;//
	int file_bytes;//bytes read
	unsigned char tempdata[10];//store temp data from file 
	bzero(tempdata,sizeof(tempdata));
	unsigned char temp;
	int i=0;
	//unsigned char *MD5_gen;
	MD5_CTX mdContext;
    MD5_Init(&mdContext);
    MD5_Update (&mdContext, path, strlen(path));
    MD5_Final (md5sum, &mdContext);



    for (i = 0; i< MD5_DIGEST_LENGTH; i++)
    {
        sprintf(&buff[2*i],"%02x", md5sum[i]);
    }


    // calculating the hash value of the given file
    //sprintf(filename,"%s.html",buff);
    printf("md5sum %s\n", buff);
	return STATUS_OK;
}


/*
i/p :URL 

o/p: Return the error type 

Function 

 Time in linux -https://en.wikipedia.org/wiki/C_date_and_time_functions
***
*/


ErrorCodes_TypeDef checkCache(char inputUrlMD5[MAXCOLSIZE],int clientSock){

//char *urlMD5;
//char MD5_temp[MD5_DIGEST_LENGTH*2];
ErrorCodes_TypeDef fileFoundCache=STATUS_OK;
char cacheList[MAXCACHESIZE];//list of Cached Files
int cacheFiledesc;// Cache File Name
static int chacleLoc;	
char messagefromCache[MAXBUFSIZE];
size_t file_bytes=0;
//urlMD5 = MD5_temp;
char fileCheck[MAXCOLSIZE];

FILE *cacheFileptr;

time_t now;
struct tm current_time;
struct tm time_file;
double diff_t=0;
time_t time1,time2;
//time_t time_file;
struct stat file_stat;


DEBUG_PRINT("Input  file %s",inputUrlMD5);
strcpy(fileCheck,inputUrlMD5);


//check file is present in array or directory 
	if((cacheFiledesc=open(fileCheck,O_RDONLY))<0){
		fileFoundCache = STATUS_ERROR_FILE_NOT_FOUND;
		perror("Cache File");
		DEBUG_PRINT("File not  found in  %d",(int)fileFoundCache);
		return fileFoundCache;
	 }else
	 {
	 	//retrieve time from file 
		DEBUG_PRINT("File found in cache %d",(int)fileFoundCache);
		//DEBUG_PRINT("retrieve Time from file  %d");


	 }
	
//Check timeout value 
	 //strstr()


	 DEBUG_PRINT("Check Expiration time");	
	// iF file is found 
	if(fileFoundCache==STATUS_OK){
		//check for timer expirtion value
		now = time(NULL);
		DEBUG_PRINT("Here1");
		if(now == NULL){
			DEBUG_PRINT("Issue in Obtaining Time ");
			fileFoundCache = STATUS_ERROR_TIME;
		}else
		{
			DEBUG_PRINT("Current Time obtained");
		}	
	}
	
	//Convert  to readable time for display 
	if(fileFoundCache == STATUS_OK){
		DEBUG_PRINT("Here2");
		current_time =*localtime(&now);
		//if(current_time!=NULL){
				
			//printf("Readable Time (current)=> %s",asctime(current_time));	
			stat(fileCheck, &file_stat);
			time_file = *localtime(&(file_stat.st_mtime));
			
			time1 = mktime(&current_time);
			time2 = mktime(&time_file);
			//printf("time 1 %lf\n",(double)(&time1) );
			//printf("time 2 %lf\n",(double)(&time2) );
			diff_t= difftime(time1,time2);
			
			//printf("Readable Time from file => %s",asctime(time_file));
			printf("New Diff in time %f secs\n",diff_t);
			if(diff_t > MAX_TIME_OUT ){	
				printf("New File from host required");
				fileFoundCache = STATUS_ERROR_FILE_NOT_FOUND;
				return fileFoundCache;
			}
		//}
		//else
		//{
			DEBUG_PRINT("Issue in converting to  readable Time ");

			//may put a error condition 
		//}
	}

	
	if (fileFoundCache==STATUS_OK){
		DEBUG_PRINT("Read and Send file to client from Cache");
		//
		//while((file_bytes = fread(&messagefromCache,MAXBUFSIZE,100,cacheFileptr)) >= 0){//Read data from files
		while((file_bytes= read(cacheFiledesc,messagefromCache,MAXBUFSIZE))>0){
			write(clientSock,messagefromCache,sizeof(messagefromCache));
			DEBUG_PRINT("Retreving from Cache %d",(int)file_bytes);

		}	
		DEBUG_PRINT("Completed cahce retrival ");
	}	

	close(cacheFiledesc);
	//fclose(cacheFileptr);
	
	DEBUG_PRINT("Return Value %d",(int)fileFoundCache);
	return fileFoundCache;


}


/***************************************************************************
*Service responsible for request to external service (acting as a client )
*
*
*GET www.google.com HTTP/1.0
****************************************************************************/
ErrorCodes_TypeDef ProxyClientService(char requestMessage[],char *responseMessage,int clientSock,struct HttpFormats_struct *host){

	int socketproxyClient=-1;
	ErrorCodes_TypeDef connect_sucess;
	ssize_t nbytes=0;
	char messagefromServer[MAXBUFSIZE];
	char requesttoHost[MAXBUFSIZE];
	char responsefromHost[MAXBUFSIZE];
	struct hostent* targethost;
	ErrorCodes_TypeDef portFound;
	ErrorCodes_TypeDef cacheFound=STATUS_OK;
	char *retchr=NULL,*hosttemp=NULL,*tempretchr=NULL; //return for character search 

	char *temp1=NULL,*temp4=NULL;
	char temp3[MAXCOLSIZE];

	char temp2[MAXCOLSIZE],temp[MAXCOLSIZE],urltemp[MAXCOLSIZE];
	char searchchar;
	char portNumber[MAXBUFSIZE];
	struct in_addr **addr_list;
	int i=0;size_t n=0;
	FILE *cacheWrite;
	char urlMD5check[MAXMD5LENGTH];
	//char MD5_temp[MAXMD5LENGTH];
	//urlMD5check = &MD5_temp;
	char tempurlMD5[MAXMD5LENGTH];
	int cacheWritedesc;



	//char cwd[1024];
	//chdir("/path/to/change/directory/to");
	//getcwd(cwd, sizeof(cwd));
	//DEBUG_PRINT("Current working dir: %s\n", cwd);


	if ((socketproxyClient= socket(AF_INET , SOCK_STREAM , 0))<0){
	    printf("Issue in Creating Socket,Try Again !! %d\n",socketproxyClient);
	    perror("Socket --> Exit ");			        
		//exit(-1); // what needs to be done ?
		return STATUS_ERROR;
	}
    //}
    //DEBUG_PRINT("Input Message =>%s \n Client to Proxy SocKet=>%d \n",requestMessage  ,socketproxyClient);
	

	//bzero(urlMD5check,sizeof(urlMD5check));
	//bzero(tempurlMD5,sizeof(tempurlMD5));
	cacheFound=STATUS_ERROR_SOCKET_NOT_WRITTEN;// other than cache found 	
	bzero(urlMD5check,sizeof(urlMD5check));
	bzero(tempurlMD5,sizeof(tempurlMD5));
	//MD5String(host->HttpURLValue,&urlMD5check);
	MD5Cal(host->HttpURLValue,&urlMD5check);

	DEBUG_PRINT("MD5  value of url  %s\n",urlMD5check);
	strcpy(tempurlMD5,urlMD5check);
	DEBUG_PRINT("Copy of MD5  value of url  %s\n",tempurlMD5);
	//check if file is available in Cache 
	cacheFound =checkCache(tempurlMD5,clientSock);
	DEBUG_PRINT("Cache  status %d => %s",(int)cacheFound,urlMD5check);


	if(cacheFound != STATUS_OK){
			//Check the url ,if port avaialble and  split in to http <host> <port>
			//Back up of intial host url
			DEBUG_PRINT("Split the HOST  %s",host->HttpURLValue);
			strcpy(temp,host->HttpURLValue);
			strcpy(temp2,host->HttpURLValue);
			strcpy(temp3,host->HttpURLValue);


			DEBUG_PRINT("temp => %s , temp2 => %s",temp,temp2);

			//Reinialize portFound
			portFound=STATUS_OK;
			searchchar = ':';

			retchr =strrchr(&host->HttpURLValue[6],searchchar);
			if(retchr){
				DEBUG_PRINT("Found %s",retchr);
				portFound=STATUS_OK;
			}
			else
			{
				portFound = STATUS_ERROR;
				DEBUG_PRINT("Not found");
			}
			
			//split the url 
			strcpy(urltemp,host->HttpURLValue);//backup the url 
			temp1=strtok(host->HttpURLValue,"//");
			if(portFound!=STATUS_OK){
				host->port = 80;
				temp1 = strtok(NULL,"/");
				DEBUG_PRINT("After 1st split Temp 1 %s",temp1);
				strcpy(temp2,temp1);
			}// 
			else{
				if(portFound == STATUS_OK){
					DEBUG_PRINT("Here1 %s",temp1);
				tempretchr=strrchr(urltemp,searchchar);

				if(tempretchr!=NULL){
						//DEBUG_PRINT("tempretchr(length %d) %s",tempretchr,sizeof(tempretchr));
						//DEBUG_PRINT("host->HttpURLValue(l %d) %s",host->HttpURLValue,strlen(host->HttpURLValue));
						//DEBUG_PRINT("temp2 %s",temp2);
						//DEBUG_PRINT("temp3 %s",temp3);
						n= tempretchr - urltemp;
						DEBUG_PRINT("urltemp %s",urltemp);
						DEBUG_PRINT("tempretchr %s",tempretchr);
						DEBUG_PRINT("temp2 %s",temp2);
						DEBUG_PRINT("len %d",n);
						memset(temp2,0,sizeof(temp2));
						strncpy(temp2,&temp3[7],(n-7));
						temp2[n+1]='\0';
					}
				
					DEBUG_PRINT("HOST %s",temp2);
					strcpy(temp1,temp2);
				}
				DEBUG_PRINT("After 1st split temp 1(port found ) %s (len %d)",temp1,strlen(temp1));

				//if(temp3){
				//	DEBUG_PRINT("Here3");
				//	strcpy(temp2,temp3);
				//	DEBUG_PRINT("After 1st split temp 2(port found ) %s (len %d)",temp2,strlen(temp2));
				//}	
			}
			
			DEBUG_PRINT("host copy = %s\n",temp2);
			if((targethost = gethostbyname(temp2))==NULL){
				perror(temp2);
				DEBUG_PRINT("Cannot get a host address %s ",temp2);
				//exit(-1);//Return error
				return STATUS_ERROR_REQUEST;

			}
			DEBUG_PRINT("Official Name %s",targethost->h_name);
			addr_list = (struct in_addr **)targethost->h_addr_list;
		    for(i = 0; addr_list[i] != NULL; i++) {
		        DEBUG_PRINT("%s ", inet_ntoa(*addr_list[i]));
		    }

			if(portFound == STATUS_OK){
				//temp1= strtok(NULL,"/");
				strncpy(portNumber,&tempretchr[1],(strlen(tempretchr)-1));
				DEBUG_PRINT("Port %s",portNumber);
				host->port=atoi(portNumber);
			}

			//extract only host name 
			//eg http://google.com/ to google.com

			strcat(temp,"^]");
			DEBUG_PRINT("New Temp => %s",temp);
			//emp1=strtok(temp,"//");	
			hosttemp = strstr(temp,"//");
			DEBUG_PRINT("Temp 1 => %s",hosttemp);
			
			DEBUG_PRINT("Temp 1 (2) => %s",temp1);
			/*
			if((temp1=strtok(NULL,'/'))!=NULL){
				temp1=strtok(NULL,"^]");
			}
			*/
			DEBUG_PRINT	("Path=> %s , PORT => %d",temp1,host->port);


			ProxyClient.sin_family =AF_INET;
		    //Create a socket between Proxy server and HOST    
		    ProxyClient.sin_port = htons(host->port);        		//htons() sets the port # to network byte order	
		   	//bcopy((char*)targethost->h_addr,(char*)&ProxyClient.sin_addr.s_addr,targethost->h_length);
		   	memcpy(&ProxyClient.sin_addr.s_addr,targethost->h_addr,targethost->h_length);
		   	//DEBUG_PRINT("Proxy IP %s", inet_ntoa((ProxyClient.sin_addr.s_addr)));    
		    //Connect to remote server

		    
			if (connect(socketproxyClient , (struct sockaddr *)&ProxyClient , sizeof(ProxyClient)) < 0){
		        perror("\nConnect failed. Error");
		        connect_sucess=STATUS_ERROR;
		        return STATUS_ERROR;
		        
		    }
		    else {//socket connection is successful 
						
					connect_sucess=STATUS_OK;

					//clear the buffer
				    //bzero(requestMessage,sizeof(requestMessage));
				    bzero(requesttoHost,sizeof(requesttoHost));    		
				    DEBUG_PRINT("Before Request formed %s ,%s ",requesttoHost,requestMessage);	//
		    		DEBUG_PRINT("Method =>%s",host->HttpMethodVaue);
		    		DEBUG_PRINT("url =>%s",urltemp);
		    		DEBUG_PRINT("version =>%s",host->HttpVersionValue);
		    		DEBUG_PRINT("host =>%s",temp1);
		    		// form the reuest depending on url found or not 
					//if(temp1!=NULL)
						//sprintf(requesttoHost,"GET /%s %s\r\nHost: %s\r\nConnection: close\r\n\r\n",temp1,temp,temp2);
					sprintf(requesttoHost,"%s %s %s\r\nHost: %s\r\nConnection: close\r\n\r\n",host->HttpMethodVaue,urltemp,host->HttpVersionValue,temp1);
					//else
					//	sprintf(requesttoHost,"%s\r\nHost: %s\r\nProxy-Connection: keep-alive\r\n\r\n",requestMessage,temp1);
						//sprintf(requesttoHost,"GET / %s\r\nHost: %s\r\nConnection: close\r\n\r\n",temp,temp2);
					//strcat(requesttoHost,'\0');
					//DEBUG_PRINT("Request formation\n\r%s",requestMessage);	//
					//strncpy(requesttoHost,requestMessage,sizeof(requestMessage));
					DEBUG_PRINT("Request send to HOST\n\r%s",requesttoHost);	//


			    	if(write(socketproxyClient,requesttoHost,sizeof(requesttoHost))<0){//check if request is send continously 
			    		perror("Write Target HOst Socket");
			    		return STATUS_ERROR_SOCKET_NOT_WRITTEN;
			    	}
			    	else{
				    		DEBUG_PRINT("Wait for reply");
				    		
				    		//if ((cacheWrite=fopen(urlMD5check,"wr"))==NULL){//if File  not found 
				    		if ((cacheWritedesc=open(urlMD5check,O_CREAT|O_WRONLY,S_IRUSR | S_IWUSR))<0){//if File  not found 
								DEBUG_PRINT("Cant open file to cache !! \n");
								perror(urlMD5check);
								//return STATUS_ERROR_FILE_NOT_FOUND;
							}
							
							printf("File opened%s\n", urlMD5check);
				    		//bzero((char*)responsefromHost,sizeof(responsefromHost));
				    		do
							{
								memset((char*)messagefromServer,0,sizeof(messagefromServer));
								if(nbytes=recv(socketproxyClient,messagefromServer,sizeof(messagefromServer),0)>0){//recv from server and check for non-blocking 
									//send(newsockfd,buffer,n,0);//send to client of proxy server when completed 
									write(clientSock,messagefromServer,sizeof(messagefromServer));
									DEBUG_PRINT("Sending to client @%d",clientSock);	
									//fwrite(messagefromServer,MAXPACKSIZE,50,cacheWrite);
									write(cacheWritedesc,messagefromServer,sizeof(messagefromServer));
									//strcat(responsefromHost,messagefromServer);
									//DEBUG_PRINT("Message from Target host %s",messagefromServer);	
									
								}

							}while(nbytes>0);

							//DEBUG_PRINT("Complete message from Target Hosts  \n\r%s",responsefromHost);
							
							//if(responsefromHost!=NULL){
							//	memcpy(responseMessage,responsefromHost,sizeof(responsefromHost));
							//}
							close(cacheWritedesc);
							//if(cacheWrite){
							//	free(cacheWrite);											
							//}
			    
						    	/*
								if(nbytes = recv(socketproxyClient,messagefromServer,sizeof(messagefromServer),0)<0){//recv from server and check for non-blocking 
									fprintf(stderr,"non-blocking socket not returning data  List %s\n",strerror(errno) );
								}
								else
								{
									DEBUG_PRINT("Message to client %s ",messagefromServer);
								}
								*/						
						}
					

				}
			shutdown(socketproxyClient,SHUT_RDWR);
			close(socketproxyClient);
			socketproxyClient =-1;	
	}
	else
	{
		DEBUG_PRINT("File Found in Canche ");
	}		
}






ErrorCodes_TypeDef checkRequest(char (*request)[MAXCOLSIZE],int thread_sock,char *request_data,struct HttpFormats_struct *host){

		char response_message[MAXBUFSIZE];//store message from client// 
		char path[MAXPACKSIZE],copypath[MAXPACKSIZE];
		int filedesc=0,filesize=0;
		ssize_t send_bytes=0,total_size=0;
		char sendData[MAXBUFSIZE];
		struct stat *file_stats=NULL;
		char file_type[MAXCOLSIZE];
		int total_attr_commands=0,i=0,contentimpl=0;
		char *p=NULL;
		char *lastptr=NULL;
		HTTP_METHOD method;
		
		// For POST
		char (*user)[MAXCOMMANDSIZE];
		char comp[MAXCOMMANDSIZE];
		//char (*comp)[MAXCOMMANDSIZE];
		char *ret=NULL;
		int user_attr,comp_attr;
		int j=0;




		//Check for erros in request 
		if(!strcmp(request[HttpMethod],"GET")){//if first element 
			DEBUG_PRINT("GET Method implemented");
			method =HTTP_GET;
		}
		else if (!strcmp(request[HttpMethod],"POST")){//if first element 
			DEBUG_PRINT("POST Method implemented");
			method =HTTP_POST;
		}	
		else{
			error_response("400 Bad Request",request[HttpMethod],thread_sock,request[HttpVersion],"Invalid Method");
			DEBUG_PRINT("Method isn't implemented");
			return STATUS_ERROR;
		}	
		strcpy(host->HttpMethodVaue,request[HttpMethod]);

		//check for version 
		if (!strncmp(request[HttpVersion],"HTTP/1.1",8)){//if first element 
			DEBUG_PRINT("Got HTTP 1.1");
			bzero(request[HttpVersion],16);
			strncpy(request[HttpVersion],"HTTP/1.1",8);
			
		}
		else if(!strncmp(request[HttpVersion],"HTTP/1.0",8)){
			DEBUG_PRINT("Got HTTP 1.0");
			bzero(request[HttpVersion],16);
			strncpy(request[HttpVersion],"HTTP/1.0",8);
			
		}		
		else
		{
			error_response("400 Bad Request",request[HttpVersion],thread_sock,request[HttpVersion],"Invalid HTTP-Version");
			DEBUG_PRINT("Method isn't implemented");
			return STATUS_ERROR;
		}	
		strcpy(host->HttpVersionValue,request[HttpVersion]);	
			
		DEBUG_PRINT("Check for URL");			
		
		ret = strstr(request[HttpURL],"\\");//
		if(ret)
		{	
			printf("BAD URL");			
			error_response("400 Bad Request",request[HttpURL],thread_sock,request[HttpVersion],"Invalid HTTP-URL");
			return STATUS_ERROR;
		}
		else
		{	
		DEBUG_PRINT("Cant find bad chacraters ! Good URL");

		}		
		strcpy(host->HttpURLValue,request[HttpURL]);	

		//read the defaut index file 
		memset(path,0,sizeof(path));
		
		//**acquire root path ** left 
		//strcpy(path,ROOT);
		//strcpy(path,config.document_root);

		//DEBUG_PRINT("Path before request:%s",path);
		DEBUG_PRINT("request URL:%s",request[HttpURL]);
		
		
		//Concate root path with requested URL 
		

		/*
		//check if no path/default location 		
		if(!(strncmp(request[HttpURL], "/\0", 2)))  {
			//strcat(path,"/index.html");			
			strcat(path,"/");			
			strcat(path,config.directory_index);			
		}
		else{
			//Concate root path with requested URL 
			strcat(path,request[HttpURL]);			
		}
		DEBUG_PRINT("Path after request%s   ",path);


		memset(sendData,0,sizeof(sendData));
		memset(response_message,0,strlen(response_message));
		//size of file 
		if ((filedesc=open(path,O_RDONLY))<1){//if File  not found 
			
			error_response("404 Not Found",request[HttpURL],thread_sock,request[HttpVersion],"URL Does not Exist");
			perror("File not Found");
			return STATUS_ERROR;
		}
		
		else
		{
			//send OK status 
			memset(response_message,0,strlen(response_message));
			
			//send success message
			
			strcpy(response_message,"HTTP/1.1 200 OK\r\n");
			//printf("%s",response_message);
			write(thread_sock,response_message,strlen(response_message));		
			//DEBUG_PRINT("%s",response_message);

			//for content type 
			memset(response_message,0,strlen(response_message));
			strcpy(copypath,path);
			p=strtok(copypath,".");
			if(p!=NULL)
			{
				//strncpy(file_type[0],p,strlen(p));
				//DEBUG_PRINT("1st %s",file_type[0]);
				//p=strtok(NULL,".");
				//strncpy(file_type[1],p,strlen(p));
				//DEBUG_PRINT("type %s",file_type[1]);
				DEBUG_PRINT("path searched%s",path);
				lastptr = strrchr(path,'.');
				if(lastptr){
					DEBUG_PRINT("last occurence %s",lastptr);
					*lastptr++;
					
					strcpy(file_type,lastptr);
					DEBUG_PRINT	("format %s \n",file_type);
				}
				else
				{
					
					perror("File not Found");
					DEBUG_PRINT("Could not find '.' ");error_response("404 Not Found",request[HttpURL],thread_sock,request[HttpVersion],"URL Does not Exist");
					//return -1;
				}
				//Search for Content type and assign Type supported 
				contentimpl = 0;//Initial value not found 
				for (i=0;i<maxtypesupported;i++)
				{
					if (!strcmp(file_type,&config.content_type[i][1])){
						//printf("Found Content Match");
						sprintf(response_message,"%s\r\n",config.response_type[i]);
						contentimpl = 1;
						break;
					}
					else{
						contentimpl = 0;
					}

				}

				//DEBUG_PRINT("%d %s %s",i,config.content_type[i],config.response_type[i]);
				if (!contentimpl)
				{
					error_response("501 Not Implemented",file_type,thread_sock,request[HttpVersion],"File type Not Implemented");
					printf("File type is not implemented");
					return STATUS_ERROR;
				}

				
	
				//printf("%s",response_message);
				write(thread_sock,response_message,strlen(response_message));			

			}
			else
			{
				DEBUG_PRINT("Unable to split...exit ");
				error_response("500 Internal Server Error",request[HttpURL],thread_sock,request[HttpVersion],"Invalid File Name");
				return STATUS_ERROR;
			}
			
			
			//for content lenght 
			file_stats = malloc(sizeof(struct stat));
			memset(file_stats,0,sizeof(file_stats));
			stat(path, file_stats);
			filesize = file_stats->st_size;
			//DEBUG_PRINT("File size %d",filesize);
			memset(response_message,0,strlen(response_message));
			sprintf(response_message,"Content-Length: %d\r\n\n",(int)filesize);					
			//printf("%s",response_message);
			write(thread_sock,response_message,strlen(response_message));		

			DEBUG_PRINT("%s",response_message);

			bzero(file_stats,sizeof(bzero));
			free(file_stats);
						
			DEBUG_PRINT("Reading and send File data");
			
			memset(sendData,0,sizeof(sendData));
			//send data 
			//Incoporate addition for POST Method
			if (method == HTTP_POST){
				//printf("POST  changes incoporated \n");
				//printf("Data from Client%s\n",request_data);
				
				ret = strstr(request_data,"user");
				//user=Chinmay&comp=Shah
				if(ret){
					DEBUG_PRINT("String %s",ret);
					//find the user 

					if ((user=malloc(sizeof(user)*MAXCOMMANDSIZE))){	
						user_attr=0;
						if((user_attr=splitString(ret,"=",user,4))<0)
						{
							DEBUG_PRINT("Could not split");	
						}
						else
						{
							DEBUG_PRINT("User first part %s:%s:%s",user[1],user[2],user[3]);
							j=0;
							while(user[2][j]!='&' && j<MAXCOMMANDSIZE){
								comp[j]=user[2][j];
								j++;
							}
							if(j>MAXCOMMANDSIZE)
							{
								printf("Cant Find &");
							}
							else
							{	
								sprintf(response_message,"<html>\n\r<head>\r\n<h1>POST Data for test</h1>\n\r</head>\n\r<body>\n\r<pre>\n\r %s %s </pre>\n\r</body>\n</html>\n\r",comp,user[3]);
								send(thread_sock,response_message,sizeof(response_message),0);		
							}	
							
						}	
						free(user);				
						
					}
					else
					{
						DEBUG_PRINT("Unable to alloacte");
					}
				}	
				else
				{
					DEBUG_PRINT("Didnt find user");
				}	
				
				//return 0;
			}
			else{
				DEBUG_PRINT("No changes incoporated ");
			}

			//printf("\nPath%s\n",path );
			while((send_bytes=read(filedesc,sendData,MAXBUFSIZE))>0){
				DEBUG_PRINT("%s\n",sendData); 
				total_size += send_bytes;
				send(thread_sock,sendData,send_bytes,0);		
				memset(sendData,0,sizeof(sendData));
			}
			DEBUG_PRINT("Total size read %d",(int)total_size);
			memset(response_message,0,strlen(response_message));
			strcpy(response_message,"\nCompleted\r\n");
			//printf("%s",response_message);
			//write(thread_sock,response_message,strlen(response_message));		

			close(filedesc);//close the file opened 
		}
		//
		*/


		return STATUS_OK;
}

//Client connection for each client 

void *client_connections(void *client_sock_id)
{
	
	
	int total_attr_commands=0,i=0;
	int thread_sock = (int*)(client_sock_id);
	ssize_t read_bytes=0;
	char message_client[MAXPACKSIZE];//store message from client 
	char message_bkp[MAXPACKSIZE];//store message from client 
	char (*split_attr)[MAXCOLSIZE];
	DEBUG_PRINT("passed Client connection %d\n",(int)thread_sock);
	char messagetoClient[MAXBUFSIZE];
	ErrorCodes_TypeDef errorcode=STATUS_OK;
	struct HttpFormats_struct temphost;
	struct HttpFormats_struct *host;
	host=&temphost;
	

	
		DEBUG_PRINT("Before message recieved");
		// Recieve the message from client  and reurn back to client 
		if((read_bytes =recv(thread_sock,message_client,MAXPACKSIZE,0))>0){

			//printf("request from client %s\n",message_client );
			memcpy(message_bkp,message_client,sizeof(message_client));//backup of orginal message 
			DEBUG_PRINT("Message length%d\n",(int)strlen(message_client) );
			DEBUG_PRINT("Message %s\n",message_client);
			
			if ((split_attr=malloc(sizeof(split_attr)*MAXCOLSIZE))){	
				strcpy(split_attr[HttpVersion],"HTTP/1.0");//Default
				strcpy(split_attr[HttpMethod],"GET");//Default
				strcpy(split_attr[HttpURL],"index.html");//No data 
	
				if((total_attr_commands=splitString(message_client," ",split_attr,4))<0)
				{
					DEBUG_PRINT("Error in split\n");

					//printf("%s\n", );
					bzero(message_client,sizeof(message_client));	
					bzero(split_attr,sizeof(split_attr));	
					return NULL;
				}
				else
				{
					
					bzero(message_client,sizeof(message_client));	
					bzero(split_attr,sizeof(split_attr));				
					//DEBUG_PRINT("Cannot split input request");
				}
				//print the split value 
				
				for(i=0;i<total_attr_commands;i++){
					DEBUG_PRINT("In split of input %d %s\n",i,split_attr[i]);
				}
				
				//printf("in client connections%s\n",message_bkp);
				if(checkRequest(split_attr,thread_sock,message_bkp,host)!=STATUS_OK){
					DEBUG_PRINT("Request unsuccessful \n");
				}
				else{
					DEBUG_PRINT("Request checked successfully => %s\n",message_bkp);
					//Proxy 
					//Processing the inout from client  to 
					//if(messagetoClient=(char*)calloc(MAXBUFSIZE,sizeof(char))<0){
					//	printf("Cant alloacte memory ");
					//}
					//else{
						// check 
						if (ProxyClientService(message_bkp,&messagetoClient,thread_sock,host)==STATUS_OK){
							
							DEBUG_PRINT("Write back to client %s",messagetoClient);
							//write(thread_sock,messagetoClient,strlen(messagetoClient));
						}
						else{
							printf("Issue request to Server");
						}	
						
					//}
				}
						
				//free alloaction of memory 
				for(i=0;i<total_attr_commands;i++){
					free((*split_attr)[i]);
				}
				
				free(split_attr);//clear  the request recieved 
				/*
				if(messagetoClient){
					DEBUG_PRINT("Clear  the memory");
					free(messagetoClient);
				}
				*/
						
			}
			else 
			{
					error_response("500 Internal Server Error",split_attr[HttpURL],thread_sock,split_attr[HttpVersion],"Invalid File Name");
					perror("alloacte 2d pointer");
					exit(-1);
			}		
			
			//check for resources in cache (hashing )
		}
		if (read_bytes < 0){
			perror("recv from client failed ");
			return NULL;

		}
	
	DEBUG_PRINT("Completed \n");
	//Closing SOCKET
    shutdown (thread_sock, SHUT_RDWR);         //All further send and recieve operations are DISABLED...
    close(thread_sock);
    thread_sock=-1;
	//free(thread_sock);//free the connection 

	//free(client_sock_id);//free the memory 
	return 1 ;
	
}


int main (int argc, char * argv[] ){
	char request[MAXPACKSIZE];             //a request to store our received message
	
	int *mult_sock=NULL;//to alloacte the client socket descriptor
	pthread_t client_thread;
	int i=0;

	DEBUG_PRINT("In main");
	/*
		//Configuration file before starting the Web Server 
		DEBUG_PRINT("Reading the config file ");
		maxtypesupported=config_parse("ws.conf");

		// Print the Configuration 
		DEBUG_PRINT("Confiuration Obtain");
		
		//Check for file support available or not 
		if (!maxtypesupported)
		{
			printf("Zero File Type Supported !! Check Config File\n");
			exit(-1);
		}
		else
		{	DEBUG_PRINT("Type Supported");
			for (i=0;i<maxtypesupported;i++)
			{
				DEBUG_PRINT("%d %s %s",i,config.content_type[i],config.response_type[i]);
			}
		}
	*/	
	/******************
	  This code populates the sockaddr_in struct with
	  the information about our socket
	 ******************/
	bzero(&server,sizeof(server));                    //zero the struct
	server.sin_family = AF_INET;                   //address family
	server.sin_port = htons(atoi(argv[1]));        //htons() sets the port # to network byte order
	DEBUG_PRINT("Port %s",argv[1]);  
	/*
	//Check if Port is present or not 
	if (strcmp(config.listen_port,"")){
		DEBUG_PRINT("Port %s",config.listen_port);
		if(atoi(config.listen_port) <=1024){
			printf("\nPort Number less than 1024!! Check configuration file\n");
			exit(-1);
		}
		else
		{
			server.sin_port = htons(atoi(config.listen_port));        		//htons() sets the port # to network byte order
		}	
		
	}
	else
	{	
		printf("\nPort Number not found !! Check configuration file");
		exit(-1);
	}
	*/
	server.sin_addr.s_addr = INADDR_ANY;           //supplies the IP address of the local machine
	remote_length = sizeof(struct sockaddr_in);    //size of client packet 

	/*
	//check if document root directory present 
	if (strcmp(config.document_root,"")){
		DEBUG_PRINT("Root %s",config.document_root);
	}
	else
	{	
		printf("\nRoot Directory not found !! Check configuration file\n");
		exit(-1);
	}

	if (strcmp(config.directory_index,"")){
		DEBUG_PRINT("Index %s",config.directory_index);
	}
	else
	{	
		printf("Default File not found !! Check configuration file\n");
		//exit(-1);
	}

	//Keepalive for pipelining 
	DEBUG_PRINT("KeepaliveTime %s",config.keep_alive_time);
	*/
	//Causes the system to create a generic socket of type TCP (strean)
	if ((server_sock =socket(AF_INET,SOCK_STREAM,0)) < 0){
		DEBUG_PRINT("unable to create tcp socket");
		exit(-1);
	}
	

	/******************
	  Once we've created a socket, we must bind that socket to the 
	  local address and port we've supplied in the sockaddr_in struct
	 ******************/
	DEBUG_PRINT("Before Bind accepted\n");  
	if (bind(server_sock, (struct sockaddr *)&server, sizeof(server)) < 0){
		close(server_sock);
		printf("unable to bind socket\n");
		exit(-1);
	}
	//
	DEBUG_PRINT("Bind accepted");
	if (listen(server_sock,LISTENQ)<0)
	{
		close(server_sock);
		perror("LISTEN");
		exit(-1);
	}


	DEBUG_PRINT("Server is running wait for connections");

	//Accept incoming connections 
	while((client_sock = accept(server_sock,(struct sockaddr *) &client, (socklen_t *)&remote_length))){
		if(client_sock<0){	
			perror("accept  request failed");
			exit(-1);
			close(server_sock);
		}
		DEBUG_PRINT("connection accepted  %d \n",(int)client_sock);	
		mult_sock = (int *)malloc(1);
		if (mult_sock== NULL)//allocate a space of 1 
		{
			perror("Malloc mult_sock unsuccessful");
			close(server_sock);
			exit(-1);
		}
		DEBUG_PRINT("Malloc successfully\n");
		//bzero(mult_sock,sizeof(mult_sock));
		*mult_sock = client_sock;

		DEBUG_PRINT("connection accepted  %d \n",*mult_sock);	
		//Create the pthread 
		if ((pthread_create(&client_thread,NULL,client_connections,(void *)(*mult_sock)))<0){
			close(server_sock);
			perror("Thread not created");
			exit(-1);

		}				
		/*
		//as it does  have to wait for it to join thread ,
		//does not allow multiple connections 
		if(pthread_join(client_thread, NULL) == 0)
		 printf("Client Thread done\n");
		else
		 perror("Client Thread");
		 */
		free(mult_sock);
		DEBUG_PRINT("Freed");

	}	
	if (client_sock < 0)
	{
		perror("Accept Failure");
		close(server_sock);
		exit(-1);
	}
		


	close(server_sock);
	


}
		

