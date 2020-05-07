/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package signatureclient;

/**
 *
 * @author User
 */
 
import java.io.*;
import java.security.*;
import java.security.spec.*;
 
public class KeyManager {
    
    static String algo = "DSA";
 
	public static void main(String args[]) {
//		KeyManager keyManager = new KeyManager();
            try {
                    String path = "res/";

                    KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algo);

                    keyGen.initialize(1024);
                    KeyPair generatedKeyPair = keyGen.genKeyPair();

                    System.out.println("Generated Key Pair");
                    dumpKeyPair(generatedKeyPair);
                    SaveKeyPair(path, generatedKeyPair);

                    KeyPair loadedKeyPair = LoadKeyPair(path);
                    System.out.println("Loaded Key Pair");
                    dumpKeyPair(loadedKeyPair);
            } catch (Exception e) {
                    e.printStackTrace();
                    return;
            }
	}
        public static KeyPair generate() throws NoSuchAlgorithmException {
            
                    KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algo);

                    keyGen.initialize(1024);
                    KeyPair generatedKeyPair = keyGen.genKeyPair();
                    return generatedKeyPair;
        }
	public static void dumpKeyPair(KeyPair keyPair) {
		PublicKey pub = keyPair.getPublic();
		System.out.println("Public Key: " + getHexString(pub.getEncoded()));
 
		PrivateKey priv = keyPair.getPrivate();
		System.out.println("Private Key: " + getHexString(priv.getEncoded()));
	}
        
        public static String dumpPublic(KeyPair keypair) {
            return getHexString(keypair.getPublic().getEncoded());
        }
        
        public static String dumpPrivate(KeyPair keypair) {
            return getHexString(keypair.getPrivate().getEncoded());
        }
 
	public static String getHexString(byte[] b) {
		String result = "";
		for (int i = 0; i < b.length; i++) {
			result += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
		}
		return result;
	}
 
	public static void SaveKeyPair(String path, KeyPair keyPair) throws IOException {
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();
 
		// Store Public Key.
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
				publicKey.getEncoded());
		FileOutputStream fos = new FileOutputStream(path + "/public.key");
		fos.write(x509EncodedKeySpec.getEncoded());
		fos.close();
 
		// Store Private Key.
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
				privateKey.getEncoded());
		fos = new FileOutputStream(path + "/private.key");
		fos.write(pkcs8EncodedKeySpec.getEncoded());
		fos.close();
	}
 
	public static KeyPair LoadKeyPair(String path)
			throws IOException, NoSuchAlgorithmException,
			InvalidKeySpecException {
            String algorithm = algo;
		// Read Public Key.
		File filePublicKey = new File(path + "/public.key");
		FileInputStream fis = new FileInputStream(path + "/public.key");
		byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
		fis.read(encodedPublicKey);
		fis.close();
 
		// Read Private Key.
		File filePrivateKey = new File(path + "/private.key");
		fis = new FileInputStream(path + "/private.key");
		byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
		fis.read(encodedPrivateKey);
		fis.close();
 
		// Generate KeyPair.
		KeyFactory keyFactory = KeyFactory.getInstance(algo);
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
				encodedPublicKey);
		PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
 
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
				encodedPrivateKey);
		PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
 
		return new KeyPair(publicKey, privateKey);
	}
        
        public static PublicKey LoadPublicKey(String path)
			throws IOException, NoSuchAlgorithmException,
			InvalidKeySpecException {
            String algorithm = algo;
		// Read Public Key.
		File filePublicKey = new File(path);
		FileInputStream fis = new FileInputStream(path);
		byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
		fis.read(encodedPublicKey);
		fis.close();
 
		// Generate KeyPair.
		KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
				encodedPublicKey);
		PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
 
		return publicKey;
	}
}