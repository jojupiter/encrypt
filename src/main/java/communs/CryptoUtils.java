package communs;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.soap.Text;
import java.io.File;
import java.io.FileOutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

public class CryptoUtils {
	/*
	* Cette fonctionn permet de de generer le vecteur initial
	* Il s'agit d'octect aleatoire de 12 ou 16 octects
	* numBytes represente le nombre d'octects
	* */
	public static byte[] getRandomNonce(int numBytes) {
		byte[] nonce = new byte[numBytes];
		new SecureRandom().nextBytes(nonce);
		return nonce;
	}
	// AES Key devired from ramdom word
	public static SecretKey getAESKey(int keysize) throws NoSuchAlgorithmException {
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(keysize, SecureRandom.getInstanceStrong());
		return keyGen.generateKey();
	}
	// AES key derived from a password
	public static SecretKey getAESKeyFromPassword(char[] password, byte[] salt)
			throws NoSuchAlgorithmException, InvalidKeySpecException {

		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		KeySpec spec = new PBEKeySpec(password, salt, 65536, ValueUtils.AES_KEY_BIT);
		SecretKey secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
		return secret;
	}
	public static byte [] convertStringToByte(String plainText){
		byte[] data = plainText.getBytes();
		return data;
	}
	public static String convertByteToString(byte[] data){
		return null;
	}
	public static String convertSecretKeyToString (SecretKey secretKey) throws Exception{
		String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
		return encodedKey;
	}
	public static SecretKey convertStringToSecretKey(String key){
		// decode the base64 encoded string
		byte[] decodedKey = Base64.getDecoder().decode(key);
		// rebuild key using SecretKeySpec
		SecretKey secretKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
		return secretKey;
	}

	public static void readFile(File file) throws Exception{
		String str = "Hello";
		FileOutputStream outputStream = new FileOutputStream(file);
		byte[] strToBytes = str.getBytes();
		outputStream.write(strToBytes);

		outputStream.close();
	}


}
