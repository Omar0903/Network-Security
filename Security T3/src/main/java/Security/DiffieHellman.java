package Security;

import java.util.Arrays;
import java.util.List;

public class DiffieHellman {
    public List<Integer> getKeys(int q, int alpha, int xa, int xb) {
        int ya = (int) modPow(alpha, xa, q); // Alice's public key
        int yb = (int) modPow(alpha, xb, q); // Bob's public key

        // Compute shared secret (should be equal on both sides)
        int sharedKeyA = (int) modPow(yb, xa, q); // Alice computes: YB^xA mod q
        int sharedKeyB = (int) modPow(ya, xb, q); // Bob computes:   YA^xB mod q

        return Arrays.asList(sharedKeyA, sharedKeyB);
    }
    public static long modPow(long base, long exp, long mod) {
        long result = 1;
        base = base % mod;

        while (exp > 0) {
            if ((exp & 1) == 1) {
                result = (result * base) % mod;
            }
            exp >>= 1;
            base = (base * base) % mod;
        }
        return result;
    }

    //throw new UnsupportedOperationException("Not implemented yet.");

}
