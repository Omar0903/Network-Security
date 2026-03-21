package Security;

import java.util.*;

public class MonoalphabeticCipher {

    public String analyse(String plainText, String cipherText) {
        cipherText = cipherText.toLowerCase();
        plainText = plainText.toLowerCase();
        char[] key = new char[26];

        Arrays.fill(key, '\0');

        for (int i = 0; i < plainText.length(); i++) {
            int m = plainText.charAt(i) - 'a';
            key[m] = cipherText.charAt(i);
        }

        for (int i = 0; i < 26; i++) {
            if (key[i] == '\0') {
                for (int j = 0; j < 26; j++) {
                    char c = (char) (j + 'a');
                    boolean found = false;
                    for (int k = 0; k < 26; k++) {
                        if (key[k] == c) {
                            found = true;
                            break;
                        }
                    }
                    if (!found) {
                        key[i] = c;
                        break;
                    }
                }
            }
        }
        return new String(key);
    }

    public String decrypt(String cipherText, String key) {
        cipherText = cipherText.toLowerCase();
        key = key.toLowerCase();
        StringBuilder plainText = new StringBuilder();

        for (int i = 0; i < cipherText.length(); i++) {
            char letter = cipherText.charAt(i);
            int j = key.indexOf(letter);

            if (j != -1) {
                char l = (char) (j + 'a');
                plainText.append(l);
            }
        }
        return plainText.toString();
    }

    public String encrypt(String plainText, String key) {
        plainText = plainText.toLowerCase();
        key = key.toLowerCase();
        StringBuilder ciphertext = new StringBuilder();

        for (int i = 0; i < plainText.length(); i++) {
            int index = plainText.charAt(i) - 'a';
            ciphertext.append(key.charAt(index));
        }
        return ciphertext.toString();
    }

  public String analyseUsingCharFrequency(String cipher) {
    cipher = cipher.toLowerCase();

    // English letter frequencies
    double[] englishFreq = {
        8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015,
        6.094, 6.966, 0.153, 0.772, 4.025, 2.406, 6.749,
        7.507, 1.929, 0.095, 5.987, 6.327, 9.056, 2.758,
        0.978, 2.360, 0.150, 1.974, 0.074
    };

    int bestShift = 0;
    double bestScore = Double.MAX_VALUE;

    for (int shift = 0; shift < 26; shift++) {
        int[] freq = new int[26];
        int total = 0;

        for (int i = 0; i < cipher.length(); i++) {
            char c = cipher.charAt(i);
            if (c >= 'a' && c <= 'z') {
                char decrypted = (char) ((c - 'a' - shift + 26) % 26 + 'a');
                freq[decrypted - 'a']++;
                total++;
            }
        }

        double score = 0.0;
        for (int i = 0; i < 26; i++) {
            double observed = (freq[i] * 100.0) / total;
            double expected = englishFreq[i];
            score += Math.pow(observed - expected, 2) / expected;
        }

        if (score < bestScore) {
            bestScore = score;
            bestShift = shift;
        }
    }

    StringBuilder plain = new StringBuilder();
    for (int i = 0; i < cipher.length(); i++) {
        char c = cipher.charAt(i);
        if (c >= 'a' && c <= 'z') {
            plain.append((char) ((c - 'a' - bestShift + 26) % 26 + 'a'));
        } else {
            plain.append(c);
        }
    }

    return plain.toString();
}
}
