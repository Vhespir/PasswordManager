import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.io.*;
import java.util.Random;
import java.util.Scanner;

public class PasswordManager {

    private static final String FILE_NAME = "password_vault.txt"; // Encrypted password bank created after exiting program
    private static final String MASTER_PASSWORD = "my_master_password"; // Default master password
    private static SecretKeySpec secretKey;

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter your master password: ");
        String enteredPassword = scanner.nextLine().trim(); // Trim to remove extra spaces

        if (!enteredPassword.equals(MASTER_PASSWORD)) {
            System.out.println("Invalid master password!");
            return;
        }

        secretKey = generateAESKey(MASTER_PASSWORD);

        while (true) {
            System.out.println("\nPassword Vault Options:");
            System.out.println("1. Store Password");
            System.out.println("2. Retrieve Password");
            System.out.println("3. Change Password");
            System.out.println("4. Generate Random Password");
            System.out.println("5. Exit");
            System.out.print("Select an option: ");

            int choice = scanner.nextInt();
            scanner.nextLine();

            switch (choice) {
                case 1:
                    storePassword(scanner);
                    break;
                case 2:
                    retrievePassword(scanner);
                    break;
                case 3:
                    changePassword(scanner);
                    break;
                case 4:
                    generateAndStorePassword(scanner);
                    break;
                case 5:
                    System.out.println("Exiting...");
                    return;
                default:
                    System.out.println("Invalid option. Please try again.");
            }
        }

    }

    // Generate a valid 16-byte AES key using SHA-256
    private static SecretKeySpec generateAESKey(String key) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            byte[] keyBytes = sha.digest(key.getBytes(StandardCharsets.UTF_8));
            byte[] aesKey = new byte[16];
            System.arraycopy(keyBytes, 0, aesKey, 0, aesKey.length);
            return new SecretKeySpec(aesKey, "AES");
        } catch (Exception e) {
            throw new RuntimeException("Error generating AES key: " + e.getMessage());
        }
    }

    // Store password
    private static void storePassword(Scanner scanner) {
        System.out.print("Enter a site name: ");
        String site = scanner.nextLine().trim();

        System.out.print("Enter the password for " + site + ": ");
        String password = scanner.nextLine().trim();

        String encryptedPassword = encryptPassword(password);

        if (encryptedPassword == null) {
            System.out.println("Encryption failed. Password not stored.");
            return;
        }

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(FILE_NAME, true))) {
            writer.write(site + ":" + encryptedPassword);
            writer.newLine();
            System.out.println("Password stored successfully.");
        } catch (IOException e) {
            System.out.println("Error storing password: " + e.getMessage());
        }
    }

    // Retrieve password
    private static void retrievePassword(Scanner scanner) {
        System.out.print("Enter the site name to retrieve password: ");
        String site = scanner.nextLine().trim().toLowerCase(); // Convert input to lowercase

        try (BufferedReader reader = new BufferedReader(new FileReader(FILE_NAME))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(":", 2);
                if (parts.length == 2 && parts[0].trim().toLowerCase().equals(site)) { // Convert stored site name to lowercase
                    String encryptedPassword = parts[1].trim();
                    String decryptedPassword = decryptPassword(encryptedPassword);

                    if (decryptedPassword != null) {
                        System.out.println("Password for " + parts[0].trim() + ": " + decryptedPassword);
                    } else {
                        System.out.println("Error decrypting password.");
                    }
                    return;
                }
            }
            System.out.println("Site not found in the vault.");
        } catch (IOException e) {
            System.out.println("Error retrieving password: " + e.getMessage());
        }
    }

    // Change password
    private static void changePassword(Scanner scanner) {
        System.out.print("Enter the site name for which you want to change the password: ");
        String site = scanner.nextLine().trim().toLowerCase(); // Convert input to lowercase

        File file = new File(FILE_NAME);
        StringBuilder updatedData = new StringBuilder();
        boolean found = false;

        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(":", 2);
                if (parts.length == 2 && parts[0].trim().toLowerCase().equals(site)) { // Compare in lowercase
                    System.out.print("Enter the new password: ");
                    String newPassword = scanner.nextLine().trim();
                    String encryptedPassword = encryptPassword(newPassword);
                    updatedData.append(parts[0].trim()).append(":").append(encryptedPassword).append("\n");
                    found = true;
                } else {
                    updatedData.append(line).append("\n");
                }
            }
        } catch (IOException e) {
            System.out.println("Error reading password file: " + e.getMessage());
            return;
        }

        if (!found) {
            System.out.println("Site not found in the vault.");
            return;
        }

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
            writer.write(updatedData.toString());
            System.out.println("Password updated successfully.");
        } catch (IOException e) {
            System.out.println("Error updating password: " + e.getMessage());
        }
    }

    // Generate a random password and store into a site
    private static void generateAndStorePassword(Scanner scanner) {
        while (true) { // Loop to allow regeneration of passwords
            System.out.print("Enter the desired password length: ");
            int length = scanner.nextInt();
            scanner.nextLine(); // Consume newline

            // Ensure the length is reasonable
            if (length < 6) {
                System.out.println("Password length must be at least 6 characters.");
                continue; // Ask again if invalid length
            }

            // Generate password
            String password = generateRandomPassword(length);
            System.out.println("Generated password: " + password);

            // Give options to the user
            System.out.println("\nWhat would you like to do?");
            System.out.println("1. Store in site");
            System.out.println("2. Regenerate");
            System.out.println("3. Return to main menu");
            System.out.print("Select an option: ");

            int option = scanner.nextInt();
            scanner.nextLine(); // Consume newline

            switch (option) {
                case 1:
                    System.out.print("Enter a site name to store the password: ");
                    String site = scanner.nextLine().trim();

                    String encryptedPassword = encryptPassword(password);
                    if (encryptedPassword == null) {
                        System.out.println("Encryption failed. Password not stored.");
                        return;
                    }

                    try (BufferedWriter writer = new BufferedWriter(new FileWriter(FILE_NAME, true))) {
                        writer.write(site + ":" + encryptedPassword);
                        writer.newLine();
                        System.out.println("Password stored successfully.");
                    } catch (IOException e) {
                        System.out.println("Error storing password: " + e.getMessage());
                    }
                    return; // Exit after storing

                case 2:
                    System.out.println("Regenerating password...\n");
                    continue; // Loops back and generates a new password

                case 3:
                    System.out.println("Returning to main menu...");
                    return; // Exit method to return to the main menu

                default:
                    System.out.println("Invalid option. Please try again.");
            }
        }
    }

    private static String generateRandomPassword(int length) {
        Random random = new Random();
        String letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        String numbers = "0123456789";
        String specialChars = "!@#$%^&*_-+=<>?~";
        String allChars = letters + numbers + specialChars;

        StringBuilder password = new StringBuilder();

        // Ensure at least one of each type
        password.append(letters.charAt(random.nextInt(letters.length())));
        password.append(numbers.charAt(random.nextInt(numbers.length())));
        password.append(specialChars.charAt(random.nextInt(specialChars.length())));

        // Fill the rest randomly
        for (int i = 3; i < length; i++) {
            password.append(allChars.charAt(random.nextInt(allChars.length())));
        }

        // Shuffle to randomize order
        return shuffleString(password.toString());
    }

    // Utility function to shuffle a string
    private static String shuffleString(String input) {
        char[] array = input.toCharArray();
        Random random = new Random();
        for (int i = 0; i < array.length; i++) {
            int randomIndex = random.nextInt(array.length);
            char temp = array[i];
            array[i] = array[randomIndex];
            array[randomIndex] = temp;
        }
        return new String(array);
    }

    // Encryption with padding and Base64 encoding
    private static String encryptPassword(String password) {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedBytes = cipher.doFinal(password.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encryptedBytes).trim();
        } catch (Exception e) {
            System.out.println("Error encrypting password: " + e.getMessage());
            return null;
        }
    }

    // Base64 decoding before decrypting
    private static String decryptPassword(String encryptedPassword) {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedPassword.trim()));
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            System.out.println("Error decrypting password: " + e.getMessage());
            return null;
        }
    }
}