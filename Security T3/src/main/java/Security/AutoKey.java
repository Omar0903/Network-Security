package Security;

public class AutoKey {
   public String analyse(String plainText, String cipherText) {
        plainText = plainText.toLowerCase();
        cipherText = cipherText.toLowerCase();

        int len = plainText.length();
        StringBuilder extendedKey = new StringBuilder();

        for (int i = 0; i < len; i++) {
            int p = plainText.charAt(i) - 'a';
            int c = cipherText.charAt(i) - 'a';
            int k = (c - p + 26) % 26;
            extendedKey.append((char) (k + 'a'));
        }

        for (int keyLen = 1; keyLen <= len; keyLen++) {
            String key = extendedKey.substring(0, keyLen);
            String rest = extendedKey.substring(keyLen);

            if (rest.equals(plainText.substring(0, len - keyLen))) {
                return key;
            }
        }

        return "";
    }

    public String decrypt(String cipherText, String key) {
        cipherText = cipherText.toLowerCase();
        key = key.toLowerCase();

        StringBuilder plainText = new StringBuilder();
        StringBuilder autoKey = new StringBuilder(key);

        for (int i = 0; i < cipherText.length(); i++) {
            int c = cipherText.charAt(i) - 'a';
            int k = autoKey.charAt(i) - 'a';
            int p = (c - k + 26) % 26;
            char ch = (char) (p + 'a');
            plainText.append(ch);
            autoKey.append(ch);
        }

        return plainText.toString();
    }

    public String encrypt(String plainText, String key) {
        plainText = plainText.toLowerCase();
        key = key.toLowerCase();
        int len = plainText.length();

        // Extend key using the plaintext
        StringBuilder autoKey = new StringBuilder(key);
        if (autoKey.length() < len) {
            int diffLen = len - autoKey.length();
            for (int i = 0; i < diffLen; i++) {
                autoKey.append(plainText.charAt(i));
            }
        }

        StringBuilder cipherText = new StringBuilder();
        for (int i = 0; i < len; i++) {
            int p = plainText.charAt(i) - 'a';
            int k = autoKey.charAt(i) - 'a';
            cipherText.append((char) (((p + k) % 26) + 'a'));
        }
        return cipherText.toString();
    }
}
