package Security;
import java.util.*;

public class ColumnarCipher {

    public List<Integer> analyse(String plainText, String cipherText) {
        plainText = plainText.toLowerCase();
        cipherText = cipherText.toUpperCase();

        for (int keyLen = 2; keyLen <= plainText.length(); keyLen++) {
            if (plainText.length() % keyLen != 0) {
                continue;
            }

            List<Integer> nums = new ArrayList<>();
            for (int i = 1; i <= keyLen; i++) {
                nums.add(i);
            }

            List<List<Integer>> perms = new ArrayList<>();
            generatePermutations(nums, 0, perms);

            for (List<Integer> key : perms) {
                String enc = encrypt(plainText, key);
                if (enc.equalsIgnoreCase(cipherText)) {
                    return key;
                }
            }
        }

        return new ArrayList<>();
    }

    private void generatePermutations(List<Integer> arr, int index, List<List<Integer>> perms) {
        if (index == arr.size()) {
            perms.add(new ArrayList<>(arr));
            return;
        }

        for (int i = index; i < arr.size(); i++) {
            Collections.swap(arr, index, i);
            generatePermutations(arr, index + 1, perms);
            Collections.swap(arr, index, i);
        }
    }


    public String decrypt(String cipherText, List<Integer> key) {
        int cipherSize = cipherText.length();
        int rows = (int) Math.ceil((double) cipherSize / key.size());
        char[][] grid = new char[rows][key.size()];
        int count = 0;

        Map<Integer, Integer> keyMap = new HashMap<>();
        for (int i = 0; i < key.size(); i++) {
            keyMap.put(key.get(i) - 1, i);
        }

        int remainingCols = cipherSize % key.size();
        for (int i = 0; i < key.size(); i++) {
            for (int j = 0; j < rows; j++) {
                if (remainingCols != 0 && j == rows - 1 && keyMap.get(i) >= remainingCols) continue;
                grid[j][keyMap.get(i)] = cipherText.charAt(count++);
            }
        }

        StringBuilder result = new StringBuilder();
        for (int i = 0; i < rows; i++) {
            for (int j = 0; j < key.size(); j++) {
                result.append(grid[i][j]);
            }
        }
        return result.toString().toUpperCase().trim();
    }

    public String encrypt(String plainText, List<Integer> key) {
        int ptSize = plainText.length();
        int rows = (int) Math.ceil((double) ptSize / key.size());
        char[][] grid = new char[rows][key.size()];
        int count = 0;

        for (int i = 0; i < rows; i++) {
            for (int j = 0; j < key.size(); j++) {
                if (count >= ptSize) {
                    grid[i][j] = 'x';
                } else {
                    grid[i][j] = plainText.charAt(count++);
                }
            }
        }

        Map<Integer, Integer> keyMap = new HashMap<>();
        for (int i = 0; i < key.size(); i++) {
            keyMap.put(key.get(i) - 1, i);
        }

        StringBuilder cipherText = new StringBuilder();
        for (int i = 0; i < key.size(); i++) {
            for (int j = 0; j < rows; j++) {
                cipherText.append(Character.toUpperCase(grid[j][keyMap.get(i)]));
            }
        }
        return cipherText.toString();
    }
}
