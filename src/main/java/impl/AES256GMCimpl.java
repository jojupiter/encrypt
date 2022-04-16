package impl;

import communs.CryptoUtils;
import communs.ValueUtils;
import ifaces.EncryptFace;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.*;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.Random;
import java.util.logging.Logger;

import static java.nio.charset.StandardCharsets.UTF_8;

public class AES256GMCimpl implements EncryptFace {

	/*
	* Pour debugger l'application et voir comment chaque lignbe se comporte, nous utilisons l'objet logger
	* */
	Logger logger = Logger.getLogger(this.getClass().getName());

	@Override
	public String encryptText(String value, String token) throws Exception{
		byte[] plainText = value.getBytes(); // nous transformons le texte à chiffrer en byte[]
		byte[] iv = CryptoUtils.getRandomNonce(ValueUtils.IV_LENGTH_BYTE); // il s'agit du vecteur initial necessaire au chiffrement AES
		SecretKey secretkey= CryptoUtils.convertStringToSecretKey(token);
		Cipher cipher = Cipher.getInstance(ValueUtils.AESGCM_ALGO);
		cipher.init(Cipher.ENCRYPT_MODE,secretkey, new GCMParameterSpec(ValueUtils.TAG_LENGTH_BIT, iv));
		byte[] encryptedText  = cipher.doFinal(plainText);
		byte[] encryptedTextWithIvSalt = ByteBuffer.allocate(iv.length  + encryptedText.length)
				.put(iv)
				.put(encryptedText)
				.array();
		return  Base64.getEncoder().encodeToString(encryptedTextWithIvSalt);
	}

	@Override
	public File encryptFile(File file, String token, String pathOutput) throws Exception {
		Path path = Paths.get(pathOutput);
		SecretKey secretKey = CryptoUtils.convertStringToSecretKey(token);

		byte[] iv = CryptoUtils.getRandomNonce(ValueUtils.IV_LENGTH_BYTE);
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey,new GCMParameterSpec(ValueUtils.TAG_LENGTH_BIT, iv));
		FileInputStream inputStream = new FileInputStream(file);
		logger.info("BEFORE IN ENCRYPT FILE ");

		byte[] inputBytes = new byte[(int) file.length()];
		inputStream.read(inputBytes);

		byte[] outputBytes = cipher.doFinal(inputBytes);

		File fileEncryptOut = new File(path.toUri());
		FileOutputStream outputStream = new FileOutputStream(fileEncryptOut);
		outputStream.write(iv);
		outputStream.write(outputBytes);

		inputStream.close();
		outputStream.close();
		return fileEncryptOut;

	}

	@Override
	public File encryptLargeFile(File file, String token,byte[] iv) throws Exception {
		SecretKey secretKey = CryptoUtils.convertStringToSecretKey(token);
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey,new GCMParameterSpec(ValueUtils.TAG_LENGTH_BIT, iv));
		File fileEncryptOut = new File(file.getName()+".crypt");
		FileInputStream inputStream = new FileInputStream(file);
		FileOutputStream outputStream = new FileOutputStream(fileEncryptOut);
		byte[] block = new byte[1024];
		int count;
		String stringBlock;
		while ((count = inputStream.read(block)) != -1)
		{
			stringBlock = new String(block, UTF_8);
			logger.info("in encryptlarge block file"+block);
			String outputBlock=  encryptText(stringBlock,token);//cipher.doFinal(block);
			logger.info("in encryptlarge outputBlock file"+outputBlock);
			outputStream.write(outputBlock.getBytes(UTF_8));
		}
		inputStream.close();
		outputStream.close();
		return fileEncryptOut;
	}

	@Override
	public File decryptLargeFile(File file, String token,byte[] iv) throws Exception {

		FileInputStream inputStream = new FileInputStream(file.getPath());

		SecretKey secretKey = CryptoUtils.convertStringToSecretKey(token);
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		cipher.init(Cipher.DECRYPT_MODE, secretKey,new GCMParameterSpec(ValueUtils.TAG_LENGTH_BIT, iv));
		File fileDecryptOut = new File(file.getName()+".decrypt");
		FileOutputStream outputStream = new FileOutputStream(fileDecryptOut);
		byte[] block = new byte[1024];
		int count;
		String stringBlock;
		logger.info("in decryptlarge block file");
		while ((count = inputStream.read(block)) != -1)
		{
			stringBlock= new String(block, UTF_8);
			logger.info("in decryptlarge block file"+block);
			String  outputBlock= decryptText(stringBlock,token);//cipher.doFinal(block);
			outputStream.write(outputBlock.getBytes(UTF_8));

		}
		inputStream.close();
		outputStream.close();
		return fileDecryptOut;
	}









	@Override
	public String decryptText(String value, String token) throws  Exception{
		byte[] decode = Base64.getDecoder().decode(value.getBytes(UTF_8));
		ByteBuffer bufferEncryptedText = ByteBuffer.wrap(decode);
		byte[] iv = new byte[ValueUtils.IV_LENGTH_BYTE];
		bufferEncryptedText.get(iv);
		byte[] cipherText = new byte[bufferEncryptedText.remaining()];
		bufferEncryptedText.get(cipherText);
		Cipher cipher = Cipher.getInstance(ValueUtils.AESGCM_ALGO);
		SecretKey secretKey= CryptoUtils.convertStringToSecretKey(token);
		cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(ValueUtils.TAG_LENGTH_BIT, iv));
		byte[] plainText = cipher.doFinal(cipherText);

		return new String(plainText, UTF_8);
	}

	@Override
	public File decryptFile(File file, String token, String pathOutput) throws Exception{
		Path path = Paths.get(pathOutput);
		SecretKey secretKey = CryptoUtils.convertStringToSecretKey(token);
		FileInputStream inputStream = new FileInputStream(file);
		byte[] iv = new byte[ValueUtils.IV_LENGTH_BYTE];
		inputStream.read(iv);
		byte[] inputBytes = new byte[(int) (file.length()-iv.length)];
		inputStream.read(inputBytes);
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		cipher.init(Cipher.DECRYPT_MODE, secretKey,new GCMParameterSpec(ValueUtils.TAG_LENGTH_BIT, iv));
		byte[] outputBytes = cipher.doFinal(inputBytes);
		File fileEncryptOut = new File(path.toUri());
		FileOutputStream outputStream = new FileOutputStream(fileEncryptOut);
		outputStream.write(outputBytes);
		inputStream.close();
		outputStream.close();
		return fileEncryptOut;
	}

	@Override
	public String generateToken() throws Exception{
		String initalValue= "INITIAL VALUE TO GENERATE PASSWORD";
		byte[] salt = CryptoUtils.getRandomNonce(ValueUtils.SALT_LENGTH_BYTE);
		SecretKey secretKey =  CryptoUtils.getAESKeyFromPassword(initalValue.toCharArray(),salt);
		return  CryptoUtils.convertSecretKeyToString(secretKey); // le token est la cle secrete; il est generere avec le sel et le mot de passe
	}

	@Override
	public SecretKey generateSecretKey() throws Exception{
		String initalValue= "INITIAL VALUE TO GENERATE PASSWORD";
		byte[] salt = CryptoUtils.getRandomNonce(ValueUtils.SALT_LENGTH_BYTE);
		SecretKey secretKey =  CryptoUtils.getAESKeyFromPassword(initalValue.toCharArray(),salt);
		return  secretKey; // le token est la cle secrete; il est generere avec le sel et le mot de passe
	}




}
