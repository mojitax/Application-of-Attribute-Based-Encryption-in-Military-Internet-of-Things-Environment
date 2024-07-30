package mystreamsapp;

import org.apache.kafka.clients.admin.NewTopic;

public class KafkaMessageGenerator {
	
    private static final String ENCRYPT_ALGO = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;
    private static final int AES_KEY_BIT = 256;
    
    private static final Charset UTF_8 = StandardCharsets.UTF_8;

    private static Properties kafkaStreamsAppProp = new Properties();
    private static Properties messageGenAppProp = new Properties();

    private static String INPUT_TOPIC = "medical-in";


    public static void main(final String[] args) throws Exception {
        runProducer();
    }

    public static void runProducer() throws Exception {

        String homePath = System.getProperty("user.home");
        String kafkaStreamsAppConfigPath = homePath + "/kafkastream.properties";
        String messageGenAppPConfigPath = homePath + "/message_gen.properties";

        kafkaStreamsAppProp.load(new FileInputStream(kafkaStreamsAppConfigPath));
        INPUT_TOPIC = kafkaStreamsAppProp.getProperty("KAFKA_INPUT_TOPIC");

        messageGenAppProp.load(new FileInputStream(messageGenAppPConfigPath));

        Properties properties = new Properties();
        properties.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, kafkaStreamsAppProp.getProperty("BOOTSTRAP_SERVERS"));
        properties.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        properties.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class);

        try(Producer<String, String> producer = new KafkaProducer<>(properties)) {

            Callback callback = (metadata, exception) -> {
                if(exception != null) {
                    System.out.printf("Producing records encountered error %s %n", exception);
                } else {
                    System.out.printf("Record produced - offset - %d timestamp - %d %n", metadata.offset(), metadata.timestamp());
                }

            };

            Random r = new Random();

            int msgNb = Integer.parseInt(messageGenAppProp.getProperty("MSG_COUNT"));
            int modNb = Integer.parseInt(messageGenAppProp.getProperty("ID_COUNT"));
            String policyScheme = messageGenAppProp.getProperty("POLICY");
            System.out.printf("Policy %s ", policyScheme);
            String alghSpec = "HmacSHA256";
            
            //Mock --> fingerprint
        	String entityFingerprint = "secret123";
        	//Mock --> sha256(fingerprint)
        	MessageDigest digest = MessageDigest.getInstance("SHA-256");
        	byte[] encodedEntityFingerprintHash = digest.digest(entityFingerprint.getBytes(StandardCharsets.UTF_8));
        	System.out.println(encodedEntityFingerprintHash);
        	
        	SecretKey secretKey = getAESKeyFromPasswordPlain(encodedEntityFingerprintHash);
        	
        	//String salt = "0";
        	//SecretKey secretKey = getAESKeyFromPassword(new String(encodedEntityFingerprintHash, StandardCharsets.UTF_8).toCharArray(), "0".getBytes());
        	
        	//Mock --> Kafka value (message) 
        	//String originalMessage = "Hello Kafka Consumer No.";
        	
        	//String policyScheme = "(Topic: cctv2out) and (occupation: doctor) and (age: 16) and (location: usa) and (chuj: chuj) and (cipa: cipa) and (penis: penis) and (dupa: dupa) or "+
        	//		"(Topic: cctv2out) and (occupation: doctor2) and (age: 162) and (location: usa2) and (chuj: chuj2) and (cipa: cipa2) and (penis: penis2)";
        	
        	JSONObject jsonObject = new JSONObject();
        	jsonObject.put("Policy", policyScheme);
        	jsonObject.put("Message", Base64.getEncoder().encodeToString("startTimeMessage".getBytes()));   
        	
            String startMessage = jsonObject.toString();
            byte[] startTimeMessage = startMessage.getBytes("UTF-8");
            byte[] iv = getRandomNonce(IV_LENGTH_BYTE);
            byte[] encryptedText = encryptWithPrefixIV(startTimeMessage, secretKey, iv);
            
        	Mac mac_sender = Mac.getInstance(alghSpec);                	
        	SecretKeySpec secretKeySpecSender = new SecretKeySpec(encodedEntityFingerprintHash, alghSpec);
        	mac_sender.init(secretKeySpecSender);
        	
        	//StartTime HMACSHA256
        	mac_sender.update(Hex.encodeHexString(encryptedText).getBytes());
        	byte[] senderMac = mac_sender.doFinal();
        	
        	ProducerRecord<String, String> producerRecord = new ProducerRecord<>(INPUT_TOPIC,"asset1", Hex.encodeHexString(encryptedText));
        	producerRecord.headers().add("MSG_HMAC", Hex.encodeHexString(senderMac).getBytes());
        	producerRecord.headers().add("MSG_TYPE", "TIME_CALC".getBytes());
        	producer.send(producerRecord, callback); 
        	
        	
            for(int i = 1; i <= msgNb; i++){
            	
            	jsonObject = new JSONObject();
                jsonObject.put("Policy", policyScheme);
                jsonObject.put("Message", Base64.getEncoder().encodeToString(("Topic medical and occupation do").getBytes()));            
                String originalMessage = jsonObject.toString();            	
           	
                byte[] message = originalMessage.getBytes("UTF-8");
            	
            	//Encryption prep                
                iv = getRandomNonce(IV_LENGTH_BYTE);
                encryptedText = encryptWithPrefixIV(message, secretKey, iv);               
                
                //String decryptedText = decryptWithPrefixIV(encryptedText, secretKey);                
            	//Encrypted message
                //byte[] encryptedText = encryptWithPrefixIV(message, secretKey, iv);            	

            	mac_sender.update(Hex.encodeHexString(encryptedText).getBytes());
            	senderMac = mac_sender.doFinal();

            	producerRecord = new ProducerRecord<>(INPUT_TOPIC,"asset1", Hex.encodeHexString(encryptedText));
            	producerRecord.headers().add("MSG_HMAC", Hex.encodeHexString(senderMac).getBytes());
            	producerRecord.headers().add("MSG_TYPE", "DATA_MSG".getBytes());            	

            	producer.send(producerRecord, callback);  
            }
            
            jsonObject = new JSONObject();
            jsonObject.put("Policy", policyScheme);
            jsonObject.put("Message", Base64.getEncoder().encodeToString("endTimeMessage".getBytes()));            
            String endMessage = jsonObject.toString();
            byte[] endTimeMessage = endMessage.getBytes("UTF-8");
            
            iv = getRandomNonce(IV_LENGTH_BYTE);
            encryptedText = encryptWithPrefixIV(endTimeMessage, secretKey, iv); 
            
            mac_sender.update(Hex.encodeHexString(encryptedText).getBytes());
        	senderMac = mac_sender.doFinal();
            
            producerRecord = new ProducerRecord<>(INPUT_TOPIC,"asset1", Hex.encodeHexString(encryptedText));
        	producerRecord.headers().add("MSG_HMAC", Hex.encodeHexString(senderMac).getBytes());
        	producerRecord.headers().add("MSG_TYPE", "TIME_CALC".getBytes());
        	producer.send(producerRecord, callback); 
        }
    }
    
    public static void signAuthMsg() {
    	
    }
    
    // AES secret key
    public static SecretKey getAESKey(int keysize) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keysize, SecureRandom.getInstanceStrong());
        return keyGen.generateKey();
    }
    
    public static SecretKey getAESKeyFromPasswordPlain(byte[] plainKey)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

    	SecretKey secret = new SecretKeySpec(plainKey, 0, plainKey.length, "AES");
        return secret;

    }

    // Password derived AES 256 bits secret key
    public static SecretKey getAESKeyFromPassword(char[] password, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        // iterationCount = 65536
        // keyLength = 256
        PBEKeySpec spec = new PBEKeySpec(password, salt, 65536, 256);        
        SecretKey secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        return secret;

    }
    
    public static byte[] getRandomNonce(int numBytes) {
        byte[] nonce = new byte[numBytes];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }
    
    // hex representation
    public static String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    // print hex with block size split
    public static String hexWithBlockSize(byte[] bytes, int blockSize) {

        String hex = hex(bytes);

        // one hex = 2 chars
        blockSize = blockSize * 2;

        // better idea how to print this?
        List<String> result = new ArrayList<>();
        int index = 0;
        while (index < hex.length()) {
            result.add(hex.substring(index, Math.min(index + blockSize, hex.length())));
            index += blockSize;
        }

        return result.toString();

    }
    
    // AES-GCM needs GCMParameterSpec
    public static byte[] encrypt(byte[] pText, SecretKey secret, byte[] iv) throws Exception {

        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, secret, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
        byte[] encryptedText = cipher.doFinal(pText);
        return encryptedText;

    }

    // prefix IV length + IV bytes to cipher text
    public static byte[] encryptWithPrefixIV(byte[] pText, SecretKey secret, byte[] iv) throws Exception {

        byte[] cipherText = encrypt(pText, secret, iv);

        byte[] cipherTextWithIv = ByteBuffer.allocate(iv.length + cipherText.length)
                .put(iv)
                .put(cipherText)
                .array();
        return cipherTextWithIv;

    }

    public static String decrypt(byte[] cText, SecretKey secret, byte[] iv) throws Exception {

        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, secret, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
        byte[] plainText = cipher.doFinal(cText);
        return new String(plainText, UTF_8);

    }

    public static String decryptWithPrefixIV(byte[] cText, SecretKey secret) throws Exception {

        ByteBuffer bb = ByteBuffer.wrap(cText);

        byte[] iv = new byte[IV_LENGTH_BYTE];
        bb.get(iv);
        //bb.get(iv, 0, iv.length);

        byte[] cipherText = new byte[bb.remaining()];
        bb.get(cipherText);

        String plainText = decrypt(cipherText, secret, iv);
        return plainText;

    }
}