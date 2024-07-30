package main

import (
	//"crypto/rand"
	//b64 "encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/base64"
	
	"crypto/rand"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"crypto/aes"
	"crypto/cipher"
	
	//"io"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path"
	"time"
	"sort"
	"math"

	"github.com/IBM/sarama"
	"github.com/cloudflare/circl/abe/cpabe/tkn20"
	
	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	mspID        = "Org1MSP"
	cryptoPath   = "/home/test/project/hyperfabric/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com"
	certPath     = cryptoPath + "/users/User1@org1.example.com/msp/signcerts/cert.pem"
	keyPath      = cryptoPath + "/users/User1@org1.example.com/msp/keystore/"
	tlsCertPath  = cryptoPath + "/peers/peer0.org1.example.com/tls/ca.crt"
	peerEndpoint = "localhost:7051"
	gatewayPeer  = "peer0.org1.example.com"
)

// newGrpcConnection creates a gRPC connection to the Gateway server.
func newGrpcConnection() *grpc.ClientConn {
	certificate, err := loadCertificate(tlsCertPath)
	if err != nil {
		panic(err)
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(certificate)
	transportCredentials := credentials.NewClientTLSFromCert(certPool, gatewayPeer)

	connection, err := grpc.Dial(peerEndpoint, grpc.WithTransportCredentials(transportCredentials))
	if err != nil {
		panic(fmt.Errorf("failed to create gRPC connection: %w", err))
	}

	return connection
}

// newIdentity creates a client identity for this Gateway connection using an X.509 certificate.
func newIdentity() *identity.X509Identity {
	certificate, err := loadCertificate(certPath)
	if err != nil {
		panic(err)
	}

	id, err := identity.NewX509Identity(mspID, certificate)
	if err != nil {
		panic(err)
	}

	return id
}

func loadCertificate(filename string) (*x509.Certificate, error) {
	certificatePEM, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}
	return identity.CertificateFromPEM(certificatePEM)
}

// newSign creates a function that generates a digital signature from a message digest using a private key.
func newSign() identity.Sign {
	files, err := os.ReadDir(keyPath)
	if err != nil {
		panic(fmt.Errorf("failed to read private key directory: %w", err))
	}
	privateKeyPEM, err := os.ReadFile(path.Join(keyPath, files[0].Name()))

	if err != nil {
		panic(fmt.Errorf("failed to read private key file: %w", err))
	}

	privateKey, err := identity.PrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		panic(err)
	}

	sign, err := identity.NewPrivateKeySign(privateKey)
	if err != nil {
		panic(err)
	}

	return sign
}

type Message struct {
	Policy        string `json:"policy"`
	MessageBase64 string `json:"message"`
}

func main() {

	// The gRPC client connection should be shared by all Gateway connections to this endpoint
	clientConnection := newGrpcConnection()
	defer clientConnection.Close()

	id := newIdentity()
	sign := newSign()

	// Create a Gateway connection for a specific client identity
	gw, err := client.Connect(
		id,
		client.WithSign(sign),
		client.WithClientConnection(clientConnection),
		// Default timeouts for different gRPC calls
		client.WithEvaluateTimeout(5*time.Second),
		client.WithEndorseTimeout(15*time.Second),
		client.WithSubmitTimeout(5*time.Second),
		client.WithCommitStatusTimeout(1*time.Minute),
	)
	if err != nil {
		panic(err)
	}
	defer gw.Close()

	// Override default values for chaincode and channel name as they may differ in testing contexts.
	chaincodeName := "basic"
	if ccname := os.Getenv("CHAINCODE_NAME"); ccname != "" {
		chaincodeName = ccname
	}

	channelName := "mychannel"
	if cname := os.Getenv("CHANNEL_NAME"); cname != "" {
		channelName = cname
	}

	network := gw.GetNetwork(channelName)
	contract := network.GetContract(chaincodeName)

	//=========================

	consumerTopic := flag.String("consumer", "medical-in", "Consumer")
	flag.Parse()

	if *consumerTopic == "" {
		fmt.Println("Consumer topic is required.")
		return
	}
	// Kafka consumer configuration
	config := sarama.NewConfig()
	consumer, err := sarama.NewConsumer([]string{"localhost:9092"}, config)
	if err != nil {
		log.Fatalf("Failed to create consumer: %v", err)
	}
	defer consumer.Close()
	pkstring := "040604000200153ccd12eb9a48c25e573d0d0c80aad3c86e7d72872edbe44c3ef133ded1b7a28933170902bb634afb1d4261736ffc030d374a7a29dede6f90000dfa54e4311d38789fb561d7f9871c6b314bafc5c4c89c91ebe93dcd6c5dbd0066cbd60615a30408d58961fbc42ccb460863290483e2ee4a6ef9553e283291cb1a1989190ef9b67562b66013792544c543dcf2ffcb7b0b6aee714f211587cde039fb5095b02dff4d072b0ad37cc88cbb686e66ca8e43c2d57d56792ce865add87cfbf719aa900e27cc15bbe2d407a1f2e341f5faa8cb3d786e72e841ef379caaf5653b958b41e4e006eac3d964fe52d6f34a8343dd7504b701693079bba9a84726b6f854b140d2c2c27f8c9f4a8eae42b0f8b7dcf611a21fecdb363af1d6f6eb421b496de22114b6aa7df5baab8d115e65ecc89f42aaacb60d5c97b8905efcbebb8d4e5451f59975c68e32e1672cdbf73e95e8f4ed2f088253675f20c767269c4620c3f9a8b6e57b68233f607547037f2a7ebb2832048b6e0ff08e26240ea563ebb2110483c6195db81e4a940eba93c2fd62d27eb5f2358f051a6d18541860e8791cc7b506f61ddbe41b752466ca880a1fe47206dc620db22fa9c0f891dc8d68fd120c429b432d2938ecc715718271765e29df5eba72a9d6f28ef8e8a761008fe8e1e813feb5143fecdc70fb464a9a4a68f5899499440bba15fb0fb3391daab3088f406caeaa543d710002f9838d14a5d94f13f5ade31533dcfb4ef2f9240fbbebd65a4c188071da7faec38cee25a480c60c3af8288e582ea84e4ebb92c8ad07c73fbf49ff7717e4f2da572abbd5bcba5de779ab4a352e5e171913fcfaf621473716354474b30c31604ddcf737c4d4086ef6094a22d10bb152f9068086ba900ace9dd3de8d2b1115a53c28571893299553635fb934d002292147dad23f3c99e7638b3a99a52b00b8007ba552baeb975d17f147a6d6ca59c67fb786fcfcd350e18289d84e44922b335aa775a6975f7239b39f5e8a2ae005e2fcfe2462ae78d15e06b9bef4c9831a0f870c2919f857631dc6a20ca0d839a96a7c33281cc522f6b9861f934a2cb80d5da804caa942e72ad2b587019b7d4b124aa359df59d65cc1ec00b4fbfac6beeece9405eed8816c68bcee56542e861e0e33b673ed40e0ca639b25bd5e9e73aebd5e50d5cd83f39624e27c90b212949092644de1c2efa04b5da8fd04087d7d1510dee9727fe15018c7189752b0d38d781813b85f582c36058afd3d2101e97ac3270fbf00bf622cec621837f72b3f568c012ca1356f2625ecb95bd5ab1b9090a282e79a3a133ff9da3f9a360256d7ce626ca07eb7628e808516211121ab631cc503f5dae00cbc90f9bf041a9bb44149e0b2a1511238747249f4e7cbc92f81425dd8c1fd5dbf250a4c4159f15f099715350ce2dbca9fde5ce712a81eedf6e24424c76672d57306cf768e8cf56fc24eb1f1c65a976a166ba74bbc28c32cb1faefe0022dc44a83e350d135f339195a374a60c6238b18ef425fd4e8622997c3e3be9abb3b02e1a3ab3f5e1b01191016443472193944237b6d6c7756b3eeae23e677a4e0ed5640e4d6c408b2bb3c65d86a98ddb0c45385b265439766e943115057159015fba17e6e7cf6773141a891ca4ed53a15ad9f32a8132e7fecfb4ad3dd894340c5958c61a856a1a1f8e9fe5ee1db6ae710e51f92047d36f75ebe880ae8e5a61b73668efc6069122fa7c5b564c724e9e91bee37f98e1bb15c44c5c80185a666950a6084a7904a15690bb319a1ed9995856e928471dbbb746adc65465a922170430e3204e34435dbb5d34838f2268fd6a00bed717cfab8960f0dca4f6f0b1d3409c0eccbc0cbb0856735b87848c287bd1c50b478e0cf4ad88c32176c6a71d36b6c19aebdc92e79577ad8ca8268e735a2d538ba19bcef6f773a715996e50d9c9aaad0ee2a78bf4aae5783783d0be4de705e0a5dd9a5e238ed2ecc76f48ca71cbfeefc41bd401023a990e9c47db743eb994d431513ffdc8e2823e2502402cdb62ff016b952e33bf9e1146d60affb84f2213358dd1a9f598c5211ee744e27f154d4dd0ff3eb2718df5ac6db4112ce68f9de350f83db54aaea710c2bde92197a5360bb8d582b8260b5203d091aac2ffbfdb3573f92b37a7a59556d8862d997dac99f4a44020300020017d4c8f8130e71318ebbd561dc3fe517d62189771352440f66a64a1c3d917ba451b7482b71c8fa23a23165211362d962160ef77302ff5bacc015ca63e28057c4777349e4b91aef206b1bbc1771d0c85dd89a15b6a182bf99bcbf5c30849e56850c6ce38cf288b94d3c4103fdbbe11cd546f55e5230c695430cfe13b1539965a8b0fb3f80da0feaf13e5fac3abe39a53307ff551c257dfe17df7b99c8721390a86f913bcfa811716b9488dc16e2f6c1b4ffaaf4b28b592d417fb54a61f49b12500ff32ca7af9fec436cd5db3c6874e3f2011b7c058e5e2ea81540a37871018a5a20f7a13737b910f1f71d293bdef819c509a49b512a97646cbf4d0dd7620f2f1e772d9dd38e2c3bbf964205d9a3f1fed32b6a51a9577c17cbd7dac531800406b40009f1033c1dca3c7facb61476c3a7502fe60667ffdc2963a95ad3355fc8893b67e3619b10ae426b9bd9fa5d1ecfccea161572511b292bbd61a81cd2f2788214fa9d96295f9371b1bba8c4d8acd0b5487d280c161815669e0777125a1114113519bc4fd2ed11f9d2c69f6c59489f0bb0c25be02d5aa7f1475cf83eb25b6b3113caf9a5d96188101b6a3326b490030c2c0b60dd0626e87d559d9b4ee745ad2c8c3985e72a8aaa2ffa100c65d52dad3cdae21bf345bc4c26d4108dc2aa8198bf970cf71778665e673fc59054666d600da5c5752f02bba4520acf8966c0ef0614a010b0ca2e9d953570f5a20620a38f9cd503fc18a26f0b10784031dc4b2fddcb1d3eecbfce899c7f2f3959760c1232d4d0e548870660b6bfc308329d1bc04376f88404020001000d4efbf46bf65c04959bcd3507711d4ef99592fbabcbc8eaa4100a04eb34db7c16f8983e79a2d0227c59674f21ed80f00ca55ca813f261241b80253c46a49de8586d6722470afef4f300c769532ed219c9183a6a2fa81a6d86c5268d4adbade606e75a7807fe4c5da8365af9c57fd047a77b5a622b6747ea984089ae6a8f2d545cb2991feee1d65dd47f67eeb76915b80fe167641ed0f6d644fd468003d48ab5ae563a7bdf5a63daa58c37aca46f8f5cff5b1f46beccfed2d148d73afd214c45102de239837a27c220595c85ed75ad5672bc2ccabe1a8c4fc40d4ff6fa7ef9fcf4edba2c0929b616fd65dd306c15b11b0d655769c87d2b65be9bee9d9fcc5b36e0986e5cfe938ec07f5dc566ea72215ad545003e47127f3f7351e4988332ae32073f609ee12b111ce615d9510763eb8958fbb488af31df619316c9cc2b7a314b4b8d55389392f7176bea35bf7ed7eb35078a695ced0186f9f9fc1059e75b1249f8b8259567d58e4f940a7b094b16b0c7cde8c07556ae76dd2bb72199a22250aa02ca8e6041f2929a56a3531a6f0a4cf59db243a00a432181cc8e6cf15b7e175f178feeddb514faafe71f18ebcd232d1218ead9e13c8656a3943bc2d3f04725b4417bdd67e401a2d0dae9145de2859336380fa628a7536e410311fb55811cf1e103497b5f8a55f1b7981ab5986364e55df6f7cef4ac4dfaf1d8efe8db903e792b650592886b2490eb0caf3c4f6c482d1308e25d408dd68c5cec8ea53dc4e825e1f2397c6ba6fafc26340258d0cee9996bcc7d35f4f085aad00aa1812731d6e5e5156bc43417b7e1f58853f0d7f75da4f8adf955a2a1c818358ad17e0fdd66acd7e6d49fd4818b381f36da9876ce7ce1ea026c628531bf46188cfcc76ef347aca90e55ec8067a81e660c74f3db0e66d87ea252aed3559676ec410510d6caa973a90c1abde1aeb2fafc06c82d76e4ba33972227ef2034c4f9d109a29123af1e7e18291592d7be98edffb839d3e61837dcdc0cd9645948b4060af8f2afd90ea6113da732bb31133cb03b4b570ad40c58b3d6b0afa5deea6e3e4e5203aff82380db1913941693b98bb50009e009ff4e42832e4575c7b82343f1d6336ff95d6bbf0499fe62471b14b390b5d6356f86357d325806626519416d45117c09619a8bba0d1c71fbe97c19bd6f98ae8b48c37c5bbabfdc3838fbd44bd9166660395f1012e899080232d90e31ee031e7be736b49fba4d47fe37dc9e52458073d8530a955eb7b81c3c79c3cf018c06a22ebc791111560015dac31c3c558eec974ac6d3d8a2138658e9c6a8596c64d3fc5ea728b4ce392c05d8eb307904a5247e8ea6bb0a6fbe500d64ca1a1b8f43dc4e627aa9f9a11a8ef833e2d7fc6db6472aebe8228019f61f85a1528add2bfca16ce8e9c81de0324106df04ba6f72d38ef590613c1d2dbd371bb1cae427bc4828aed62a70e2c78e31f2c47f6b648e26c00ebc5b7b6244f95e08e93c24035e5a0d4ca28fbca3bf0f4b1640b8499b9dee251d1b7bb1c0b16ecc86cbb509c3a116648e9f78c2d73f604c0ad7143c66e0433ac45b1b346e4b589578406d9f25ce8a291c6f1e6b26ce6979e95466c7407357218573afa487ce07eb"
	mskstring := "c4000300020016ffdc3813aca94db83a2630bfb0107bb87468cae0b4488b50311b47b456cbae00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000263281d7ccf7ec852589948bdb25d8dbf0ab53f0d23a06ebaef80e3b08294b8d0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000104010400020005dff6dc42f772059fcedf4f32193935ba2cd53b102c0f9863e9183acb69606139629d85c97cff6a97ebdc6afb2f0f9677946793ff180cfc7cb061f32476613f50b4204a14c5efa018bf6071980248b9a294c66328d97ed6b20256bd33a1aa200154d881561d5eccec77c51ef97670608a923aff0a991aa126c4d717fc7945d467dd5d0eddd61ecd68744f26a791c4a1e0d8e539949fd0a4ac06666f86d24a941010480a6e1132dee5241f73b2945854dc6250403554e3f2ad1ea5f85e332f6622828dd523e539d0a6087d3be8db911a83f6439e22fa9982ceca733ff556e82623c0af50ef5d40e50c42d31c75f9a6fefa242e7a60a627d6170a19cff005d5f70401040002002f4618970da1899ca76fb54f2b5567844db1a6d506c3cfd2131eb720a4b40a4551eea27b880ce4e2bb0ee3f7c72051b4c939e4d53987138ad4cc2730e3028dc44650fdbfa914c67eeba3f9ae239dd8ab22982d01d0ea20fb7d8bdccd4e7ac5c64c6cecb7d5454f94ec88d3d88672f5eee4b141c0703c27f885756ec0e80711fc6277d4faa9d2b8d00572a9b3726b215e8e37b4f57cc722c2a983fa59de1b1eaf6d3cb9579e8bf12a7f4ee7652a45f3ab4925e1b070712913a3d1e4833f8d42b454f48bd6db3ce371cec3980a6ff630640dd6311f76f655d34a3ef00b0fbac1c4189b4a08137e44f8ab31ccb62c9ec62566ccb72af23039510b4b14a016cd27440401040002002aeb2f3f651a14425e06f8aa88093e6a5499d6ac579a3feb906dda3c066b3ca31ca42a0eb072d2a04786e94a85e449a367aab86f24370634d30562e82fdd32572193d358288fcceb80229f979a18252d93166f1aed5b1f49bb469b59f837680900f96058f6f7d140b8ad6e691f7ce8aeeda4e5b5859f3e7f7df6b08f86d037f100d2b5dafbd680393290ee656df7caf616c9243101d61a16c6acea8a812e8df404a1bd1edd38481edadcddd542d1187a7899ccc2145163561dcd4639b1c9b708555cc633dfc6c729342cb877fb0530a120bff2080aa7542d0a1e17628e77b7f95d90b6cbcb43c5231beaeafa0d9ad0fcc5f798d5ecd8826c235b6731b8e19bc684000400010032910c4cd573130e14fdd8dd1253fb76759f169239d0351dc98453423ae8faef52ce396400aeda4db45b07c6ffa2a96badadd87cef50942a78294c9132e2d68753ed7af2c3ee7a8293609395ec1e84b513081868c6e5995a04857328eceaa21b5530a8ade3f5ad590e8e3ee3d070b60602f6fa7e84cdf8d4ba4c3016da6f7211100074bd8d35afe2d8e49083439ab0fff8b3"

	var pk tkn20.PublicKey
	var msk tkn20.SystemSecretKey
	pkdec, _ := hex.DecodeString(pkstring)
	mskdec, _ := hex.DecodeString(mskstring)
	_ = pk.UnmarshalBinary(pkdec)
	_ = msk.UnmarshalBinary(mskdec)
	pk_byte, _ := pk.MarshalBinary()
	log.Printf("PK:#%x", pk_byte)
	msk_byte, _ := msk.MarshalBinary()
	log.Printf("MSK:#%x", msk_byte)

	// Subscribe to Kafka topic
	topic := consumerTopic
	partitionConsumer, err := consumer.ConsumePartition(*topic, 0, sarama.OffsetOldest)
	if err != nil {
		log.Fatalf("Failed to create partition consumer: %v", err)
	}
	defer partitionConsumer.Close()
	producer, err := sarama.NewSyncProducer([]string{"localhost:9092"}, nil)
	if err != nil {
		log.Fatalf("Failed to create producer: %v", err)
	}
	defer producer.Close()
	// Handle incoming messages
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt)

	doneCh := make(chan struct{})
	
	fullProcessingTimeArray := []time.Duration{}
	readAssetIDTimeArray := []time.Duration{}
	HMACCalcTimeArray := []time.Duration{}
	decryptAESTimeArray := []time.Duration{}
	encryptABETimeArray := []time.Duration{}
	
	startMessageTime := time.Now()
	startMessageTimeAddr := &startMessageTime
	
	endMessageTime := time.Duration(0)
	endMessageTimeAddr := &endMessageTime
	
	defer func() {
	
		percentile99 := 0.99
		percentile95 := 0.95
		percentile90 := 0.90	
		
		/*******************************************************/
		fmt.Println("Start Time = ", startMessageTime)
		fmt.Println("Processing Duration = ", endMessageTime)	
		
	
		/*******************************************************/
	
		fmt.Println("== FullProcessingTime ===")
		
		sort.Slice(fullProcessingTimeArray, func(i, j int) bool {
		    return fullProcessingTimeArray[i] < fullProcessingTimeArray[j]
		})
		
		/*for _, v := range fullProcessingTimeArray {
 		   fmt.Println(v)
		}*/
		
		nTimesFP := len(fullProcessingTimeArray)
		FPTimeSum := time.Duration(0)
		
		minTimeFP := fullProcessingTimeArray[0]
		minTimeFPMemAddr := &minTimeFP
		
		maxTimeFP := fullProcessingTimeArray[0]
		maxTimeFPMemAddr := &maxTimeFP
				
		for i := 0; i < nTimesFP; i++ {
			FPTimeSum += (fullProcessingTimeArray[i])
			
			*minTimeFPMemAddr = minTime(minTimeFP, fullProcessingTimeArray[i])
			*maxTimeFPMemAddr = maxTime(minTimeFP, fullProcessingTimeArray[i])
    		}
    		
    		avgFP := (time.Duration(FPTimeSum)) / (time.Duration(nTimesFP))
    		fmt.Println("Sum = ", FPTimeSum, "\nAverage = ", avgFP, "\nMin = ", minTimeFP, "\nMax = ", maxTimeFP)
    		
    		nb99TimeFP := int(math.Floor(percentile99*float64(nTimesFP)))
    		nb95TimeFP := int(math.Floor(percentile95*float64(nTimesFP)))
		nb90TimeFP := int(math.Floor(percentile90*float64(nTimesFP)))    		
    		
    		p99FPTimeSum := time.Duration(0)
    		p95FPTimeSum := time.Duration(0)
    		p90FPTimeSum := time.Duration(0)
    		
    		for i := 0; i < nb99TimeFP; i++ {
			p99FPTimeSum += (fullProcessingTimeArray[i])
    		}
    		
    		for i := 0; i < nb95TimeFP; i++ {
			p95FPTimeSum += (fullProcessingTimeArray[i])
    		}
    		
    		for i := 0; i < nb90TimeFP; i++ {
			p90FPTimeSum += (fullProcessingTimeArray[i])
    		}
    		p99AvgFP := (time.Duration(p99FPTimeSum)) / (time.Duration(nb99TimeFP))
		p95AvgFP := (time.Duration(p95FPTimeSum)) / (time.Duration(nb95TimeFP))
		p90AvgFP := (time.Duration(p90FPTimeSum)) / (time.Duration(nb90TimeFP))
    		
    		fmt.Println("Avg Percentile", percentile99, " of ", nTimesFP, "messages = ", p99AvgFP)
		fmt.Println("Avg Percentile", percentile95, " of ", nTimesFP, "messages = ", p95AvgFP)
		fmt.Println("Avg Percentile", percentile90, " of ", nTimesFP, "messages = ", p90AvgFP)    		
    		
    		/******************************************************/
    		
    		fmt.Println("== ReadAssetID ===")
    		nTimesRA := len(readAssetIDTimeArray)
		RATimeSum := time.Duration(0)
		
		for i := 0; i < nTimesRA; i++ {
			RATimeSum += (readAssetIDTimeArray[i])
    		}
    		
    		avgRA := (time.Duration(RATimeSum)) / (time.Duration(nTimesRA))
    		fmt.Println("Sum = ", RATimeSum, "\nAverage = ", avgRA)
    		
    		/******************************************************/
    		
    		fmt.Println("== HMAC Calc ===")
    		nTimesHC := len(HMACCalcTimeArray)
		HCTimeSum := time.Duration(0)
		
		for i := 0; i < nTimesHC; i++ {
			HCTimeSum += (HMACCalcTimeArray[i])
    		}
    		
    		avgHC := (time.Duration(HCTimeSum)) / (time.Duration(nTimesHC))
    		fmt.Println("Sum = ", HCTimeSum, "\nAverage = ", avgHC)
    		
    		/******************************************************/
    		
    		fmt.Println("== AES Decrypt ===")
    		nTimesAD := len(decryptAESTimeArray)
		ADTimeSum := time.Duration(0)
		
		for i := 0; i < nTimesAD; i++ {
			ADTimeSum += (decryptAESTimeArray[i])
    		}
    		
    		avgAD := (time.Duration(ADTimeSum)) / (time.Duration(nTimesAD))
    		fmt.Println("Sum = ", ADTimeSum, "\nAverage = ", avgAD)
    		
    		/******************************************************/
    		
    		fmt.Println("== ABE Encrypt ===")
    		nTimesABE := len(encryptABETimeArray)
		ABETimeSum := time.Duration(0)
		
		minTimeABE := encryptABETimeArray[0]
		minTimeABEMemAddr := &minTimeABE
		
		maxTimeABE := encryptABETimeArray[0]
		maxTimeABEMemAddr := &maxTimeABE
		
		for i := 0; i < nTimesABE; i++ {
			ABETimeSum += (encryptABETimeArray[i])
			
			*minTimeABEMemAddr = minTime(minTimeABE, encryptABETimeArray[i])
			*maxTimeABEMemAddr = maxTime(maxTimeABE, encryptABETimeArray[i])
    		}
    		
    		avgABE := (time.Duration(ABETimeSum)) / (time.Duration(nTimesABE))
    		fmt.Println("Sum = ", ABETimeSum, "\nAverage = ", avgABE, "\nMin = ", minTimeABE, "\nMax = ", maxTimeABE)
    		
    		nb99TimeABE := int(math.Floor(percentile99*float64(nTimesABE)))
    		nb95TimeABE := int(math.Floor(percentile95*float64(nTimesABE)))
		nb90TimeABE := int(math.Floor(percentile90*float64(nTimesABE)))    		
    		
    		p99ABETimeSum := time.Duration(0)
    		p95ABETimeSum := time.Duration(0)
    		p90ABETimeSum := time.Duration(0)
    		
    		for i := 0; i < nb99TimeFP; i++ {
			p99ABETimeSum += (encryptABETimeArray[i])
    		}
    		
    		for i := 0; i < nb95TimeFP; i++ {
			p95ABETimeSum += (encryptABETimeArray[i])
    		}
    		
    		for i := 0; i < nb90TimeFP; i++ {
			p90ABETimeSum += (encryptABETimeArray[i])
    		}
    		p99AvgABE := (time.Duration(p99ABETimeSum)) / (time.Duration(nb99TimeABE))
		p95AvgABE := (time.Duration(p95ABETimeSum)) / (time.Duration(nb95TimeABE))
		p90AvgABE := (time.Duration(p90ABETimeSum)) / (time.Duration(nb90TimeABE))
    		
    		fmt.Println("Avg Percentile", percentile99, " of ", nTimesABE, "messages = ", p99AvgABE)
		fmt.Println("Avg Percentile", percentile95, " of ", nTimesABE, "messages = ", p95AvgABE)
		fmt.Println("Avg Percentile", percentile90, " of ", nTimesABE, "messages = ", p90AvgABE)    
    		    		
	}()	
	
	go func() {
		for {
			log.Printf("running")
			select {
			case msg := <-partitionConsumer.Messages():
				
				startFullProcessing := time.Now()
				
				/*
				log.Printf("GUID: %s\n", msg.Key)
				log.Printf("Msg: %s\n", msg.Value)
				
				if len(msg.Headers) > 1 {
					log.Printf("HMAC: %s\n", msg.Headers[0].Value)
				}
				
				if len(msg.Headers) > 2 {
					log.Printf("MSG TYPE: %s\n", msg.Headers[1].Value)
				}
				
				if len(msg.Headers) > 3 {
					log.Printf("IV: %s\n", msg.Headers[2].Value)
				}
				*/

				//=====================================================================
				//Read Asset ID - Time START
				startReadAssetID := time.Now()

				entityFingerpring := readAssetByID(contract, msg.Key) //Time measure
				
				//Read Asset ID - Time STOP
				elapsedReadAssetID := time.Since(startReadAssetID)
				readAssetIDTimeArray = append(readAssetIDTimeArray, elapsedReadAssetID)
				//fmt.Println("Read Asset ID took: %s", elapsedReadAssetID)
				//=====================================================================
								
				if entityFingerpring == "<error_GUID>" {
					fmt.Printf("\n***GUID NOT FOUND\n")
					continue
				}				
				
				h := sha256.New()
				h.Write([]byte(entityFingerpring))				
				hashedEntityFingerprint := fmt.Sprintf("%x", h.Sum(nil))

				originalMsg := string(msg.Value)
				originalMAC, _ := hex.DecodeString(string(msg.Headers[0].Value))

				//=====================================================================
				//HMAC Calc - Time START
				startHMACCalc := time.Now()
				
				calculatedMAC := CalcMAC(originalMsg, hashedEntityFingerprint) //Time measure
				
				//HMAC Calc - Time STOP
				elapsedHMACCalc := time.Since(startHMACCalc)
				HMACCalcTimeArray = append(HMACCalcTimeArray, elapsedHMACCalc)
				//fmt.Println("HMAC Calc took: %s", elapsedHMACCalc)
				//=====================================================================
				
				isMACEqual := ValidMAC(originalMAC, calculatedMAC)

				//fmt.Printf("\nCalcMAC %x\n", calculatedMAC)

				if  isMACEqual == true {
					//fmt.Printf("\n***MAC Verified\n")
				} else {
					fmt.Printf("\n***MAC Diffrent\n")
					continue
				}	
				
				//key := hex.EncodeToString(bytes) //encode key in bytes to string and keep as secret, put in a vault
				//fmt.Printf("key to encrypt/decrypt : %s\n", hashedEntityFingerprint)
				
				
				//=====================================================================
				//AES256 Decrypt - Time START
				startDecryptAES := time.Now()
				
				decrypted := decrypt(originalMsg, hashedEntityFingerprint) //Time measure
				//fmt.Printf("decrypted : %s\n", decrypted)
				
				//AES256 Decrypt - Time STOP
				elapsedDecryptAES := time.Since(startDecryptAES)
				decryptAESTimeArray = append(decryptAESTimeArray, elapsedDecryptAES)
				//fmt.Println("AES Decryption took: %s", elapsedDecryptAES)
				//=====================================================================
				
			
	
				//json.Unmarshal(msg.Value, &message)
				/*tempMockMessage := Message{
					//Policy:        "Topic: cctv-1-out",
					Policy:        "Topic: cctv8out",
					MessageBase64: base64.StdEncoding.EncodeToString([]byte("ranny")),
				}
				
				jsonMockMessage, err := json.Marshal(tempMockMessage)
				*/
				//jsonMockMessage, err := json.Marshal(decrypted)
				
				/*if err != nil {
					log.Fatalf("Failed to marshal message to JSON: %v", err)
				}*/
				
				var mockMessage Message
				//var mockMessage2 Message
				//json.Unmarshal([]byte(jsonMockMessage), &mockMessage2)
				json.Unmarshal([]byte(decrypted), &mockMessage)
				
				policy := tkn20.Policy{}
				
				//log.Println(policy)
				
				err = policy.FromString(mockMessage.Policy)
				
				if err != nil {
					log.Fatalf("Failed to get policy FromString: %v", err)
				}
				
				decoded, _ := base64.StdEncoding.DecodeString(mockMessage.MessageBase64)
				
				//log.Printf("Decoded: %s\n", decoded)
				
				if string(decoded) == "startTimeMessage" {
				
					*startMessageTimeAddr = time.Now()
					continue
				
				}
								
				//=====================================================================
				//ABE Encrypt - Time START
				startEncryptABE := time.Now()
				
				ciphertext, _ := pk.Encrypt(rand.Reader, policy, decoded) //Time measure
				
				//ABE Encrypt - Time STOP
				elapsedEncryptABE := time.Since(startEncryptABE)
				encryptABETimeArray = append(encryptABETimeArray, elapsedEncryptABE)
				//fmt.Println("ABE Encryption took: %s", elapsedEncryptABE)
				//=====================================================================
				
				
				//log.Printf("Ciphertext: %x\n", ciphertext)
				policymap := policy.ExtractAttributeValuePairs()
				//`(Topic: medical) and (country: US)`
				newtopic := policymap["Topic"][0]
				//encoded := base64.URLEncoding.EncodeToString(ciphertext)
				encoded := base64.StdEncoding.EncodeToString(ciphertext)
				outgoing := Message{
					Policy:        mockMessage.Policy,
					MessageBase64: encoded,
				}
				
				jsonData, err := json.Marshal(outgoing)
				if err != nil {
					log.Fatal("Error marshaling JSON:", err)
				}

				outmessage := &sarama.ProducerMessage{
					//Topic: newtopic,
					Topic: newtopic,
					Value: sarama.ByteEncoder(jsonData),
					Key:   sarama.StringEncoder(newtopic + "1"),
				}
								
				//Full Processing
				elapsedFullProcessing := time.Since(startFullProcessing)
				fullProcessingTimeArray = append(fullProcessingTimeArray, elapsedFullProcessing)
				//fmt.Println("Full processing took: %s", elapsedFullProcessing)
					
				//break					
								
				if _, _, err := producer.SendMessage(outmessage); err != nil {
					log.Printf("Failed to publish message: %v\n", err)
					continue
				}
				
				if string(decoded) == "endTimeMessage" {				
				
					*endMessageTimeAddr = time.Since(startMessageTime)			
					doneCh <- struct{}{}				
				}
				
			case <-signals:
				doneCh <- struct{}{}
				return
			}
		}
	}()

	<-doneCh
}

func maxTime(a, b time.Duration) time.Duration {
    if a < b {
        return b
    }
    return a
}

func minTime(a, b time.Duration) time.Duration {
    if a > b {
        return b
    }
    return a
}

func CalcMAC(message string, key string) []byte {

	tempKey, _ := hex.DecodeString(key)
	mac := hmac.New(sha256.New, []byte(tempKey))
	mac.Write([]byte(message))
	expectedMAC := mac.Sum(nil)
		
	return expectedMAC
}

func ValidMAC(originalMAC []byte, calculatedMAC []byte) bool {
	
	return hmac.Equal(originalMAC, calculatedMAC)
}


type TransasctionResponse struct {
    AssetID          string          `json:"assetID"`
    Comments         string          `json:"owner"`
    Fingerprint      string          `json:"color"`
    Size             int             `json:"size"`
    AppraisedValue   int             `json:"appraisedValue"` 
}

func readAssetByID(contract *client.Contract, assetID []byte) string {
	//fmt.Printf("\n--> Evaluate Transaction: ReadAsset, function returns asset attributes\n")

	evaluateResult, err := contract.EvaluateTransaction("ReadAsset", string(assetID))

	if err != nil {
		//panic(fmt.Errorf("failed to evaluate transaction: %w", err))
		return "<error_GUID>"
	}

	var transResp TransasctionResponse
	json.Unmarshal([]byte(evaluateResult), &transResp)
	
	entityFingerpring, _ := hex.DecodeString(transResp.Fingerprint)
	//fmt.Printf("\n %s \n", entityFingerpring)
	
	return string(entityFingerpring)

}

//encrypted := encrypt("Hello Encrypt", key)
//fmt.Printf("encrypted : %s\n", encrypted)

func encrypt(stringToEncrypt string, keyString string) (encryptedString string) {

	//Since the key is in string, we need to convert decode it to bytes
	key, _ := hex.DecodeString(keyString)
	plaintext := []byte(stringToEncrypt)

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	//Create a new GCM - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	//https://golang.org/pkg/crypto/cipher/#NewGCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	//Create a nonce. Nonce should be from GCM
	
	/*nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}*/
	
	nonce, _ := hex.DecodeString("21b5221ff429293a4edf463b")

	//Encrypt the data using aesGCM.Seal
	//Since we don't want to save the nonce somewhere else in this case, we add it as a prefix to the encrypted data. The first nonce argument in Seal is the prefix.
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return fmt.Sprintf("%x", ciphertext)
}

func decrypt(encryptedString string, keyString string) (decryptedString string) {

	key, _ := hex.DecodeString(keyString)
	enc, _ := hex.DecodeString(encryptedString)

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	//Create a new GCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	//Get the nonce size
	nonceSize := aesGCM.NonceSize()

	//Extract the nonce from the encrypted data
	nonce, ciphertext := enc[:nonceSize], enc[nonceSize:]

	//Decrypt the data
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	return fmt.Sprintf("%s", plaintext)
}

