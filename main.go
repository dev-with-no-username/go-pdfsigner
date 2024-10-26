package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign/sign"
	"github.com/digitorus/pdfsign/verify"
	"github.com/gin-gonic/gin"
)

// const signCertPem = `-----BEGIN CERTIFICATE-----
// MIIDBzCCAnCgAwIBAgIJAIJ/XyRx/DG0MA0GCSqGSIb3DQEBCwUAMIGZMQswCQYD
// VQQGEwJOTDEVMBMGA1UECAwMWnVpZC1Ib2xsYW5kMRIwEAYDVQQHDAlSb3R0ZXJk
// YW0xEjAQBgNVBAoMCVVuaWNvZGVyczELMAkGA1UECwwCSVQxGjAYBgNVBAMMEUpl
// cm9lbiBCb2JiZWxkaWprMSIwIAYJKoZIhvcNAQkBFhNqZXJvZW5AdW5pY29kZXJz
// Lm5sMCAXDTE3MDkxNzExMjkzNloYDzMwMTcwMTE4MTEyOTM2WjCBmTELMAkGA1UE
// BhMCTkwxFTATBgNVBAgMDFp1aWQtSG9sbGFuZDESMBAGA1UEBwwJUm90dGVyZGFt
// MRIwEAYDVQQKDAlVbmljb2RlcnMxCzAJBgNVBAsMAklUMRowGAYDVQQDDBFKZXJv
// ZW4gQm9iYmVsZGlqazEiMCAGCSqGSIb3DQEJARYTamVyb2VuQHVuaWNvZGVycy5u
// bDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAmrvrZiUZZ/nSmFKMsQXg5slY
// TQjj7nuenczt7KGPVuGA8nNOqiGktf+yep5h2r87jPvVjVXjJVjOTKx9HMhaFECH
// KHKV72iQhlw4fXa8iB1EDeGuwP+pTpRWlzurQ/YMxvemNJVcGMfTE42X5Bgqh6Dv
// kddRTAeeqQDBD6+5VPsCAwEAAaNTMFEwHQYDVR0OBBYEFETizi2bTLRMIknQXWDR
// nQ59xI99MB8GA1UdIwQYMBaAFETizi2bTLRMIknQXWDRnQ59xI99MA8GA1UdEwEB
// /wQFMAMBAf8wDQYJKoZIhvcNAQELBQADgYEAkOHdI9f4I1rd7DjOXnT6IJl/4mIQ
// kkaeZkjcsgdZAeW154vjDEr8sIdq+W15huWJKZkqwhn1sJLqSOlEhaYbJJNHVKc9
// ZH5r6ujfc336AtjrjCL3OYHQQj05isKm9ii5IL/i+rlZ5xro/dJ91jnjqNVQPvso
// oA4h5BVsLZPIYto=
// -----END CERTIFICATE-----`

// const signKeyPem = `-----BEGIN RSA PRIVATE KEY-----
// MIICWwIBAAKBgQCau+tmJRln+dKYUoyxBeDmyVhNCOPue56dzO3soY9W4YDyc06q
// IaS1/7J6nmHavzuM+9WNVeMlWM5MrH0cyFoUQIcocpXvaJCGXDh9dryIHUQN4a7A
// /6lOlFaXO6tD9gzG96Y0lVwYx9MTjZfkGCqHoO+R11FMB56pAMEPr7lU+wIDAQAB
// AoGADPlKsILV0YEB5mGtiD488DzbmYHwUpOs5gBDxr55HUjFHg8K/nrZq6Tn2x4i
// iEvWe2i2LCaSaBQ9H/KqftpRqxWld2/uLbdml7kbPh0+57/jsuZZs3jlN76HPMTr
// uYcfG2UiU/wVTcWjQLURDotdI6HLH2Y9MeJhybctywDKWaECQQDNejmEUybbg0qW
// 2KT5u9OykUpRSlV3yoGlEuL2VXl1w5dUMa3rw0yE4f7ouWCthWoiCn7dcPIaZeFf
// 5CoshsKrAkEAwMenQppKsLk62m8F4365mPxV/Lo+ODg4JR7uuy3kFcGvRyGML/FS
// TB5NI+DoTmGEOZVmZeLEoeeSnO0B52Q28QJAXFJcYW4S+XImI1y301VnKsZJA/lI
// KYidc5Pm0hNZfWYiKjwgDtwzF0mLhPk1zQEyzJS2p7xFq0K3XqRfpp3t/QJACW77
// sVephgJabev25s4BuQnID2jxuICPxsk/t2skeSgUMq/ik0oE0/K7paDQ3V0KQmMc
// MqopIx8Y3pL+f9s4kQJADWxxuF+Rb7FliXL761oa2rZHo4eciey2rPhJIU/9jpCc
// xLqE5nXC5oIUTbuSK+b/poFFrtjKUFgxf0a/W2Ktsw==
// -----END RSA PRIVATE KEY-----`

const outputFilename = "output.pdf"

func main() {
	// Create a new Gin router
	router := gin.Default()
	// Route for POST requests to "/messages"
	router.POST("/sign", func(c *gin.Context) {
		file, err := c.FormFile("file")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Unable to extract file from request",
			})
			return
		}

		// Save the file locally
		savePath := fmt.Sprintf("./%s", file.Filename)
		if err := c.SaveUploadedFile(file, savePath); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Unable to save file",
			})
			return
		}

		err = pdfSign(file.Filename, outputFilename)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Unable to sign file",
			})
			return
		}
		c.File(outputFilename)
	})

	// Start the server on port 8765
	log.Println("Server listening on port 8765")
	router.Run(":8765")
}

func pdfSign(input, output string) error {
	input_file, err := os.Open(input)
	if err != nil {
		return err
	}
	defer input_file.Close()

	output_file, err := os.Create(output)
	if err != nil {
		return err
	}
	defer output_file.Close()

	finfo, err := input_file.Stat()
	if err != nil {
		return err
	}
	size := finfo.Size()

	rdr, err := pdf.NewReader(input_file, size)
	if err != nil {
		return err
	}

	// Generate an RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048) // 2048-bit key
	if err != nil {
		log.Println("Error generating RSA key:", err)
		return err
	}

	certificate, certificateChain, err := createCertificate2(privateKey)
	if err != nil {
		log.Println("Error generating x509 certificate:", err)
		return err
	}

	signData := sign.SignData{
		Signature: sign.SignDataSignature{
			Info: sign.SignDataSignatureInfo{
				Name:        "John Doe",
				Location:    "Somewhere on the globe",
				Reason:      "My reason for signing this document",
				ContactInfo: "How you like",
				Date:        time.Now().Local(),
			},
			CertType:   sign.CertificationSignature,
			DocMDPPerm: sign.AllowFillingExistingFormFieldsAndSignaturesPerms,
		},
		Signer:            privateKey,       // crypto.Signer
		DigestAlgorithm:   crypto.SHA512,    // hash algorithm for the digest creation
		Certificate:       &certificate,     // x509.Certificate
		CertificateChains: certificateChain, // x509.Certificate.Verify()
	}

	err = sign.Sign(input_file, output_file, rdr, size, signData)

	if err != nil {
		log.Println("Error signing pdf:", err)
		return err
	}

	_, err = verify.File(output_file)
	if err != nil {
		log.Println("Error verifying signed pdf:", err)
		return err
	}

	log.Println("Signed PDF written to " + output)

	return nil
}

func createCertificate2(privateKey *rsa.PrivateKey) (x509.Certificate, [][]*x509.Certificate, error) {
	template := x509.Certificate{
		SerialNumber: big.NewInt(2024),
		Subject: pkix.Name{
			Organization:  []string{"My Organization"},
			Country:       []string{"US"},
			Province:      []string{"Province"},
			Locality:      []string{"My City"},
			StreetAddress: []string{"My Address"},
			PostalCode:    []string{"00000"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true, // Certificate Authority (can be set to false if not a CA)
	}

	rootCertificateBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		log.Printf("Failed to create certificate: %v\n", err)
		return x509.Certificate{}, [][]*x509.Certificate{}, err
	}

	rootCertificate, err := x509.ParseCertificate(rootCertificateBytes)
	if err != nil {
		log.Printf("Failed to parse certificate: %v\n", err)
		return x509.Certificate{}, [][]*x509.Certificate{}, err
	}

	roots := x509.NewCertPool()
	roots.AddCert(rootCertificate)

	certificateChain, err := rootCertificate.Verify(x509.VerifyOptions{
		Roots: roots,
	})
	if err != nil {
		log.Printf("Failed to create certificate chain: %v\n", err)
		return x509.Certificate{}, [][]*x509.Certificate{}, err
	}

	return *rootCertificate, certificateChain, nil
}

// func createCertificate() (*rsa.PrivateKey, x509.Certificate, [][]*x509.Certificate, error) {
// 	certificate_data_block, _ := pem.Decode([]byte(signCertPem))
// 	if certificate_data_block == nil {
// 		log.Println("failed to parse PEM block containing the certificate")
// 		return nil, x509.Certificate{}, [][]*x509.Certificate{}, nil
// 	}

// 	certificate, err := x509.ParseCertificate(certificate_data_block.Bytes)
// 	if err != nil {
// 		log.Printf("%s", err.Error())
// 		return nil, x509.Certificate{}, [][]*x509.Certificate{}, err
// 	}

// 	key_data_block, _ := pem.Decode([]byte(signKeyPem))
// 	if key_data_block == nil {
// 		log.Println("failed to parse PEM block containing the private key")
// 		return nil, x509.Certificate{}, [][]*x509.Certificate{}, err
// 	}

// 	privateKey, err := x509.ParsePKCS1PrivateKey(key_data_block.Bytes)
// 	if err != nil {
// 		log.Printf("%s", err.Error())
// 		return nil, x509.Certificate{}, [][]*x509.Certificate{}, err
// 	}

// 	roots := x509.NewCertPool()
// 	roots.AddCert(certificate)

// 	certificateChain, err := certificate.Verify(x509.VerifyOptions{
// 		Roots: roots,
// 	})
// 	if err != nil {
// 		log.Printf("Failed to create certificate chain: %v\n", err)
// 		return privateKey, x509.Certificate{}, [][]*x509.Certificate{}, err
// 	}

// 	return privateKey, *certificate, certificateChain, nil
// }
