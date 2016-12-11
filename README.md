pages_from_server - PASS 
pages_from_proxy  - PASS 
pages_from_server_after_cache_timeout - PASS  
prefetching       - PASS  
multithreading  - PASS for multiple clients and hosts - PARTIAL for prefetch (I have 	 implemented client connections from browser to proxy and proxy to host(server) using threading and tasks are working simultaneously .However when tried to incoporate for pre fectch introducing errors -"changes for prefetch incoporated in threads has been commented "
connection keepalive -  FAIL  -(PARTIAL) sending keepalive but havent incoporated timeout 


Videos for Demo
________________

1) Smaller versions - This demos is more polished 


2) https://youtu.be/K11F0I7XxX4
Longer version (approx 15) - Shown all test cases and error handling ,but longer as it was the first try with little fumble and mistake in terminology
- In this POST was working and it is dis continued and modified , in samller versions
- Where opencv are opening two times as I have clicked and opened in new tab , not due to any error in code 

Instructions for testing 
________________________

make - to create the executable file "webproxy"

To run proxy server 
./webproxy <PORT Number> <Caching timeout>

./webproxy 10001 100


Testing Instructions 
Clear the Mozilla cache and local proxy server cache 


For Testing with http browser (Mozilla Firefox)
1)http://www.umich.edu/~chemh215/W09HTML/SSG4/ssg6/html/Website/DREAMWEAVERPGS/first.html
Sites with more prefetching URLS
2)http://ecee.colorado.edu/~ecen5623/index_summer.html
3)http://opencv.org


For testing with PORT 
http://portquiz.net:8080/

For Testing with telnet
telnet 127.0.0.1 10001
GET http://ecee.colorado.edu/~ecen5623/index_summer.html HTTP/1.0

Error conditions
Invalid Version 
GET http://ecee.colorado.edu/~ecen5623/index_summer.html HTTP/1.2
GET http://ecee.colorado.edu/~ecen5623/index_sumer.html HTTP/1.0
HEAD http://ecee.colorado.edu/~ecen5623/index_summer.html HTTP/1.0



Implemntation of Code


1) Proxy Implementation - 

For its implementation Browers requests are sent to middle man(proxy server) which checks for method being GET and Version being HTTP/1.0 and HTTP/1.1(a socket connection establised with using client_connections call back allowing multiple connecions ) . It throws error back to browser if any condition fails otherwise it formulates the request(a socket connection b/w proxy and host server) by extracting the host and sending the following request

GET <url> HTTP/1.0     -- Method can be HTTP/1.1 as per request 
host : <host name>
Connection: Close    --- Keepalive 

After it receives its reply from the host server it cahes (discussed later) at proxy and sends back to client 


2) Caching and Timeout implementation 

For caching and searching file , MD5 hashing is been used  . Each URL which is browsed through PRoxy , a md5 hash name is found as filename and stored in cache . 
Thus whenever same url is browsed again  MD5 name matches and able to search faster within cache . 
For time out(expiry) calculation . The modified time of filename using stat has been found out and following calculation 
current time > file modified time  + <input timeout> - File fetched from HOST Server
current time < file modified time  + <input timeout> - File fetched from Proxy Server (and replaces the old file if present)

3) Prefetching Implementation 
All the links/urls from the file been accessed from host server are been found and stored in a buffer .
A new thread (disabled for current code) has been invoked and ProxyPrefetchService has been used to fetch the data from host using 1) and 2) techniques . Thus timeout and cache are implemented with cache data 


4) PORT implementation 

