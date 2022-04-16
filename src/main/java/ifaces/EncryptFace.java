package ifaces;

import javax.crypto.SecretKey;
import java.io.File;
import java.net.URI;
import java.nio.file.Path;

public interface EncryptFace {
    String encryptText(String value,String token) throws Exception;

    String decryptText(String value,String token) throws Exception;

    File encryptFile(File file, String token, String pathOutput) throws Exception; // repertoire de sortie du fichier
    File decryptFile(File file,String token, String pathOutput) throws  Exception;// repertoire de sortie du fichier


    File encryptLargeFile(File file,String token,byte[] iv)throws Exception;
    File decryptLargeFile(File file,String token,byte[] iv) throws Exception;

    String generateToken() throws Exception;
    SecretKey generateSecretKey() throws Exception;


}
