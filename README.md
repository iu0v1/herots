# HEROTS

Go (golang) package for simple and fast creation of TLS-servers and/or TLS-clients.

```
go get -u github.com/iu0v1/herots
```

For more infomation, please look at the [examples](https://github.com/iu0v1/herots/tree/master/example) and read the [doc](http://godoc.org/github.com/iu0v1/herots).

Outputs from examle server and client:
```
$ go run example/server/server.go

herots: load key pair - ok
herots: listening on localhost:9001
herots: accepted conn from 127.0.0.1:64163
2015/07/22 04:08:02 from client: Hello server! Message 1
2015/07/22 04:08:02 to client: Hello server! Message 1
2015/07/22 04:08:02 from client: Hello server! Message 2
2015/07/22 04:08:02 to client: Hello server! Message 2
2015/07/22 04:08:02 from client: Hello server! Message 3
2015/07/22 04:08:02 to client: Hello server! Message 3
2015/07/22 04:08:02 from client: 127.0.0.1:64163 send EOF


$ go run example/client/client.go

herots: load key pair - ok
herots: add cert to root CA - ok
herots: dial to localhost:9001 - ok
2015/07/22 04:08:02 client: wrote "Hello server! Message 1" (23 bytes)
2015/07/22 04:08:02 client: read "Hello server! Message 1" (23 bytes)
2015/07/22 04:08:02 client: wrote "Hello server! Message 2" (23 bytes)
2015/07/22 04:08:02 client: read "Hello server! Message 2" (23 bytes)
2015/07/22 04:08:02 client: wrote "Hello server! Message 3" (23 bytes)
2015/07/22 04:08:02 client: read "Hello server! Message 3" (23 bytes)
2015/07/22 04:08:02 client: exiting
```

Have a nice day :)
