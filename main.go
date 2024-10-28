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
