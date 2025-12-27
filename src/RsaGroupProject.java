import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;
import java.util.stream.Collectors;

public class RsaGroupProject {

    // VEREINBARTE KONSTANTEN
    private static final BigInteger E = BigInteger.valueOf(17);

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("=== RSA Gruppe Digital Signature ===");

        // 1. EIGENE SCHLÜSSEL GENERIEREN
        System.out.println("Generiere eigene Schlüssel...");
        KeyPair myKeys = generateKeys();

        System.out.println("\n------------------------------------------------");
        System.out.println("DEINE DATEN (Teile dies der anderen Gruppe mit):");
        System.out.println("Public Modulus (n): " + myKeys.n);
        System.out.println("(Public Exponent e ist fix: " + E + ")");
        System.out.println("------------------------------------------------");
        System.out.println("DEIN GEHEIMNIS (Niemandem zeigen):");
        System.out.println("Private Key (d): " + myKeys.d);
        System.out.println("------------------------------------------------\n");

        while (true) {
            System.out.println("\nWas möchtest du tun?");
            System.out.println("1 - Eine eigene Nachricht signieren (Test)");
            System.out.println("2 - Signatur einer ANDEREN Gruppe verifizieren");
            System.out.println("3 - Nachricht für eine ANDERE Gruppe verschlüsseln");
            System.out.println("4 - Eine empfangene Geheimnachricht entschlüsseln");
            System.out.println("0 - Beenden");
            System.out.print("Auswahl: ");

            String choice = scanner.nextLine();

            switch (choice) {
                case "1":
                    handleSelfSign(scanner, myKeys);
                    break;
                case "2":
                    handleVerifyExternal(scanner);
                    break;
                case "3":
                    handleEncryptForExternal(scanner);
                    break;
                case "4":
                    handleDecryptOwn(scanner, myKeys);
                    break;
                case "0":
                    System.out.println("Programm beendet.");
                    return;
                default:
                    System.out.println("Ungültige Eingabe.");
            }
        }
    }

    // =================================================================
    // INTERAKTIVE MENU-FUNKTIONEN
    // =================================================================

    private static void handleSelfSign(Scanner scanner, KeyPair keys) {
        System.out.print("Gib die Nachricht ein: ");
        String msg = scanner.nextLine();
        List<BigInteger> sig = sign(msg, keys.d, keys.n);
        System.out.println("Generierte Signatur: " + sig.toString());
    }

    private static void handleVerifyExternal(Scanner scanner) {
        System.out.println("\n--- Verifikation (Daten der anderen Gruppe eingeben) ---");
        try {
            System.out.print("Gib das n (Modulus) der anderen Gruppe ein: ");
            BigInteger otherN = new BigInteger(scanner.nextLine().trim());

            System.out.print("Gib die ursprüngliche Nachricht ein (Klartext): ");
            String msg = scanner.nextLine();

            System.out.print("Gib die Signatur ein (Format [123, 456, ...]): ");
            String sigString = scanner.nextLine();
            List<BigInteger> signature = parseInputToList(sigString);

            boolean isValid = verify(msg, signature, otherN);

            if (isValid) {
                System.out.println(">>> ERGEBNIS: Signatur ist GÜLTIG (OK) <<<");
            } else {
                System.out.println(">>> ERGEBNIS: Signatur ist UNGÜLTIG (Fehler) <<<");
            }
        } catch (Exception e) {
            System.out.println("Fehler bei der Eingabe: " + e.getMessage());
        }
    }

    private static void handleEncryptForExternal(Scanner scanner) {
        System.out.println("\n--- Verschlüsseln (für Empfänger) ---");
        try {
            System.out.print("Gib das n (Modulus) des EMPFÄNGERS ein: ");
            BigInteger receiverN = new BigInteger(scanner.nextLine().trim());

            System.out.print("Gib die geheime Nachricht ein: ");
            String secret = scanner.nextLine();

            List<BigInteger> encrypted = encryptMessage(secret, receiverN);
            System.out.println("Verschlüsselte Nachricht (sende dies an den Empfänger):");
            System.out.println(encrypted.toString());
        } catch (Exception e) {
            System.out.println("Fehler: " + e.getMessage());
        }
    }

    private static void handleDecryptOwn(Scanner scanner, KeyPair keys) {
        System.out.println("\n--- Entschlüsseln (eigene Post) ---");
        try {
            System.out.print("Gib die verschlüsselte Liste ein (Format [123, ...]): ");
            String cipherString = scanner.nextLine();
            List<BigInteger> cipherText = parseInputToList(cipherString);

            String plainText = decryptMessage(cipherText, keys.d, keys.n);
            System.out.println("Entschlüsselte Nachricht: " + plainText);
        } catch (Exception e) {
            System.out.println("Fehler beim Parsen/Entschlüsseln: " + e.getMessage());
        }
    }

    // =================================================================
    // LOGIK IMPLEMENTIERUNG (CORE)
    // =================================================================

    public static KeyPair generateKeys() {
        SecureRandom random = new SecureRandom();
        BigInteger p, q, n, phi;

        while (true) {
            p = BigInteger.probablePrime(10, random);
            q = BigInteger.probablePrime(10, random);

            if (p.equals(q)) continue;

            n = p.multiply(q);

            // Bedingung: 256 < n < 2^31 - 1
            if (n.compareTo(BigInteger.valueOf(256)) <= 0 ||
                    n.compareTo(BigInteger.valueOf(Integer.MAX_VALUE)) >= 0) {
                continue;
            }

            phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

            if (!phi.gcd(E).equals(BigInteger.ONE)) {
                continue;
            }

            BigInteger d = E.modInverse(phi);
            return new KeyPair(n, d);
        }
    }

    public static String getSha256Hex(String message) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encodedhash = digest.digest(message.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder(2 * encodedhash.length);
            for (byte b : encodedhash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // SIGNIEREN
    public static List<BigInteger> sign(String message, BigInteger d, BigInteger n) {
        String hexHash = getSha256Hex(message);
        List<BigInteger> signature = new ArrayList<>();
        for (char c : hexHash.toCharArray()) {
            BigInteger m = BigInteger.valueOf((int) c);
            signature.add(m.modPow(d, n));
        }
        return signature;
    }

    // VERIFIZIEREN
    public static boolean verify(String message, List<BigInteger> signature, BigInteger n) {
        StringBuilder decryptedHashBuilder = new StringBuilder();
        for (BigInteger s : signature) {
            BigInteger m = s.modPow(E, n);
            decryptedHashBuilder.append((char) m.intValue());
        }
        String decryptedHash = decryptedHashBuilder.toString();
        String calculatedHash = getSha256Hex(message);

        // Optional: Debug Ausgabe
        System.out.println("(Intern) Hash aus Signatur: " + decryptedHash);
        System.out.println("(Intern) Hash berechnet:    " + calculatedHash);

        return decryptedHash.equals(calculatedHash);
    }

    // VERSCHLÜSSELN (Encryption)
    public static List<BigInteger> encryptMessage(String message, BigInteger n) {
        List<BigInteger> encryptedMessage = new ArrayList<>();
        for (char c : message.toCharArray()) {
            BigInteger m = BigInteger.valueOf((int) c);
            encryptedMessage.add(m.modPow(E, n));
        }
        return encryptedMessage;
    }

    // ENTSCHLÜSSELN (Decryption)
    public static String decryptMessage(List<BigInteger> encryptedMessage, BigInteger d, BigInteger n) {
        StringBuilder decryptedText = new StringBuilder();
        for (BigInteger cipher : encryptedMessage) {
            BigInteger m = cipher.modPow(d, n);
            decryptedText.append((char) m.intValue());
        }
        return decryptedText.toString();
    }

    // HELPER: String "[1, 2, 3]" zu List<BigInteger> parsen
    private static List<BigInteger> parseInputToList(String input) {
        // Entferne eckige Klammern und Leerzeichen am Rand
        String clean = input.replace("[", "").replace("]", "").trim();
        if (clean.isEmpty()) return new ArrayList<>();

        // Splitte am Komma und mappe zu BigInteger
        return Arrays.stream(clean.split(","))
                .map(s -> new BigInteger(s.trim()))
                .collect(Collectors.toList());
    }

    static class KeyPair {
        BigInteger n;
        BigInteger d;
        public KeyPair(BigInteger n, BigInteger d) {
            this.n = n;
            this.d = d;
        }
    }
}