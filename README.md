# go-signer

Simple pdf signer, written in Go, that uses <https://github.com/digitorus/pdfsign>

## How it works

To make this signer work, you must first start the server with the following command:

```go
go run main.go
```

and then send a pdf file with the following command replacing "FILENAME" with the name of the file you want to send and which must be in the folder from which you launch the command

```bash
curl -i -X POST -H "Content-Type: multipart/form-data" -F "file=@FILENAME.pdf" http://localhost:8765/sign
```

If the call is successful, the signed pdf file will be present in this project with the name "output.pdf". If one with this name already exists, it will be overwritten. Otherwise an error will be returned.
