package communs;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public  class ValueUtils {
	public static final String AESGCM_ALGO = "AES/GCM/NoPadding";
	public static final int TAG_LENGTH_BIT = 128;
	public static final int IV_LENGTH_BYTE = 12;
	public static final int AES_KEY_BIT = 128;
	public static final int SALT_LENGTH_BYTE = 16;
	public static final Charset UTF_8 = StandardCharsets.UTF_8;
}
