import communs.CryptoUtils;
import communs.ValueUtils;
import ifaces.EncryptFace;
import impl.AES256GMCimpl;
import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;


public class EncryptApplication {
    private static String textValueCrypt;
    private static String token;
    private static String textValue="Alice a fait une transaction de 10 000FCFA à Bob";
    private static File file = new File("C:\\Users\\user\\Documents\\encrypt3\\src\\main\\resources\\test.mp4");
    private static File textLargefile = new File("C:\\Users\\user\\Documents\\encrypt3\\src\\main\\resources\\test.txt");
    private static File encryptedFile;
    private static File decryptedFile;
    private static byte[] iv;
    public static void main(String[] args){

        System.out.println("Test Encrypt");
        EncryptFace encryptFace = new AES256GMCimpl();
        try{

            token = encryptFace.generateToken();
            iv = CryptoUtils.getRandomNonce(ValueUtils.IV_LENGTH_BYTE);
            System.out.println(" Token : "+token);
            textValueCrypt= encryptFace.encryptText(textValue,token);
            System.out.println(" TextValueCrypt : "+textValueCrypt);
        }catch (Exception e){

        }
        try {
            System.out.println("Test Decrypt");
            String decryptText = encryptFace.decryptText(textValueCrypt,token);
            System.out.println("decrypt: "+decryptText);

        }catch (Exception e){

        }
        try {
            System.out.println("File Encrypt");
            String pathEncrypt = "C:\\Users\\user\\Documents\\test.crypt";
            long starTime=  System.nanoTime();
            encryptedFile= encryptFace.encryptFile(file,token,pathEncrypt);
            long endTime=  System.nanoTime();
            System.out.println("ENCRYPT GET PATH"+encryptedFile.getPath());
            System.out.println("TIME ENCRYPT  IS IN NANO SECOND"+(endTime-starTime));
        }catch (Exception e){
            e.printStackTrace();
        }
        try {
            System.out.println("File Decrypt");
            long starTime=  System.nanoTime();
            String pathDecrypt = "C:\\Users\\user\\Documents\\test.decrypt";
            decryptedFile = encryptFace.decryptFile(encryptedFile,token,pathDecrypt);
            long endTime=  System.nanoTime();
            System.out.println("TIME DECRYPT  IS IN NANO SECOND "+(endTime-starTime));
        }catch (Exception e){
            e.printStackTrace();
        }
        try {
            System.out.println("FileLarge Encrypt");

            encryptedFile= encryptFace.encryptLargeFile(textLargefile,token,iv);

        }catch (Exception e){
            e.printStackTrace();
        }
        try {
            System.out.println("FileLarge decrypt");

            encryptedFile= encryptFace.decryptLargeFile(textLargefile,token,iv);

        }catch (Exception e){
            e.printStackTrace();
        }
    }
}
