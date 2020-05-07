/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package signatureclient;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

/**
 *
 * @author User
 */
public class FileSigner {
    public static byte[] sign(PrivateKey privkey, String filePath) throws NoSuchAlgorithmException, NoSuchProviderException, SignatureException, IOException, InvalidKeyException {
        Signature dsa = Signature.getInstance("SHA1withDSA", "SUN");

        //Initialize it with the private key before using it for signing.
        dsa.initSign(privkey);

        //Supply the Signature Object the data to Be Signed
        BufferedInputStream bufin = new BufferedInputStream(new FileInputStream(filePath));
        byte[] buffer = new byte[1024];
        int len;

        while ((len = bufin.read(buffer)) >=0) {
            dsa.update(buffer, 0, len);
        }

        bufin.close();

        //Sign the data i.e. generate a signature for it
        byte[] realSig = dsa.sign();
        return realSig;
    }
    public static boolean verify(PublicKey publicKey, byte[] sigByte, String filePath) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, FileNotFoundException, IOException, SignatureException {
        Signature dsa = Signature.getInstance("SHA1withDSA", "SUN");
        dsa.initVerify(publicKey);
        
                BufferedInputStream bufin = new BufferedInputStream(new FileInputStream(filePath));
        byte[] buffer = new byte[1024];
        int len;

        while ((len = bufin.read(buffer)) >=0) {
            dsa.update(buffer, 0, len);
        }

        bufin.close();
        
        return dsa.verify(sigByte);
    }
    /*
    public static void main(String args[]) throws NoSuchAlgorithmException, NoSuchProviderException, SignatureException, IOException, InvalidKeyException, InvalidKeySpecException {
        KeyPair kp = KeyManager.LoadKeyPair("C:\\Users\\User\\Documents");
        byte[] signature = sign(kp.getPrivate());
        System.out.println(KeyManager.getHexString(signature));
                FileOutputStream fos = new FileOutputStream("src/signature");
		fos.write(signature);
		fos.close();
        System.out.println(verify(kp.getPublic(), signature));
    }
*/
}
