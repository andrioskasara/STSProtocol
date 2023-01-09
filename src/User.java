import exceptions.InvalidCertificateException;
import exceptions.InvalidSignatureException;

import javax.crypto.*;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Random;


public class User {
    private String name;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private BigInteger sharedSecret;
    private BigInteger g;
    private BigInteger p;
    private BigInteger gtoRandomNumber;
    private int randomNumber;
    private Certificate certificate;

    public User(String name) {
        this.name = name;
        try {
            HashMap<String, Object> keys = generateKeys();
            this.publicKey = (PublicKey) keys.get("public");
            this.privateKey = (PrivateKey) keys.get("private");
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
    }

    private HashMap<String, Object> generateKeys() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        HashMap<String, Object> keys = new HashMap<>();
        keys.put("public", publicKey);
        keys.put("private", privateKey);
        return keys;
    }

    private DHParameterSpec generateParameters() throws NoSuchAlgorithmException, InvalidParameterSpecException {
        AlgorithmParameterGenerator parameterGenerator = AlgorithmParameterGenerator.getInstance("DH");
        parameterGenerator.init(512);
        AlgorithmParameters parameters = parameterGenerator.generateParameters();
        return parameters.getParameterSpec(DHParameterSpec.class);
    }

    public void sendFirstMessage(User user) throws NoSuchAlgorithmException, InvalidParameterSpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidSignatureException, InvalidCertificateException {
        DHParameterSpec dhParameterSpec = generateParameters();
        this.g = dhParameterSpec.getG();
        this.p = dhParameterSpec.getP();
        Random random = new Random();
        int x = random.nextInt(Integer.MAX_VALUE);
        this.randomNumber = x;
        this.gtoRandomNumber = this.g.modPow(BigInteger.valueOf(x), this.p);
        user.receiveFirstMessage(this.g, this.p, this.gtoRandomNumber, this);
    }

    private void receiveFirstMessage(BigInteger g, BigInteger p, BigInteger gtoX, User user) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidSignatureException, InvalidCertificateException {
        this.g = g;
        this.p = p;
        Random rand = new Random();
        int y = rand.nextInt(Integer.MAX_VALUE);
        this.randomNumber = y;
        this.gtoRandomNumber = this.g.modPow(BigInteger.valueOf(y), this.p);
        this.sharedSecret = gtoX.modPow(BigInteger.valueOf(y), this.p);
        this.certificate = new Certificate(getName(), getPublicKey(), getG(), getP(), this.privateKey);

        ByteBuffer buffer = ByteBuffer.allocate(gtoRandomNumber.toByteArray().length + gtoX.toByteArray().length);
        buffer.put(gtoRandomNumber.toByteArray()).put(gtoX.toByteArray());
        byte[] concat = buffer.array();
        byte[] signed = sign(concat, this.privateKey);

        byte[] key = sharedSecret.toByteArray();
        SecretKey sharedSecretKey = new SecretKeySpec(key, 0, 32, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, sharedSecretKey);
        byte[] encryptedSignature = cipher.doFinal(signed);
        user.sendSecondMessage(this, gtoRandomNumber, certificate, encryptedSignature);
    }

    private void sendSecondMessage(User user, BigInteger gtoY, Certificate cert, byte[] encryptedSignature) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, InvalidSignatureException, InvalidCertificateException {
        //g^yx
        this.sharedSecret = gtoY.modPow(BigInteger.valueOf(this.randomNumber), this.p);
        //g^yx mod p
        SecretKey sharedSecretKey = new SecretKeySpec(sharedSecret.toByteArray(), 0, 32, "AES");
        if (verifyCertificate(cert)) {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, sharedSecretKey);
            byte[] decryptedSignature = cipher.doFinal(encryptedSignature);
            Cipher cipher2 = Cipher.getInstance("RSA");
            cipher2.init(Cipher.DECRYPT_MODE, cert.getPublicKey());
            byte[] decryptedUnsigned = cipher2.doFinal(decryptedSignature);
            ByteBuffer buffer = ByteBuffer.allocate(gtoY.toByteArray().length + gtoRandomNumber.toByteArray().length);
            buffer.put(gtoY.toByteArray()).put(gtoRandomNumber.toByteArray());
            byte[] concat = buffer.array();
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashed = digest.digest(concat);

            if (!Arrays.equals(hashed, decryptedUnsigned)) {
                throw new InvalidSignatureException("Failed to verify the signature!");
            }

            Certificate certificate = new Certificate(this.getName(), this.getPublicKey(), this.getG(), this.getP(), this.privateKey);
            ByteBuffer buffer1 = ByteBuffer.allocate(gtoRandomNumber.toByteArray().length + gtoY.toByteArray().length);
            buffer1.put(gtoRandomNumber.toByteArray()).put(gtoY.toByteArray());
            byte[] concatGxGy = buffer1.array();
            byte[] signedA = sign(concatGxGy, privateKey);

            Cipher cipher3 = Cipher.getInstance("AES");
            cipher3.init(Cipher.ENCRYPT_MODE, sharedSecretKey);
            byte[] encryptedSignedA = cipher3.doFinal(signedA);

            user.receiveSecondMessage(certificate, encryptedSignedA, gtoRandomNumber);

        } else {
            throw new InvalidCertificateException("Failed to verify the certificate!");
        }
    }

    private void receiveSecondMessage(Certificate cert, byte[] encryptedSignature, BigInteger gToX) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, InvalidSignatureException, InvalidCertificateException {
        if (verifyCertificate(cert)) {
            SecretKey sharedSecretKey = new SecretKeySpec(this.sharedSecret.toByteArray(), 0, 32, "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, sharedSecretKey);
            byte[] decryptedSignature = cipher.doFinal(encryptedSignature);
            Cipher cipher2 = Cipher.getInstance("RSA");
            cipher2.init(Cipher.DECRYPT_MODE, cert.getPublicKey());
            byte[] decryptedUnsigned = cipher2.doFinal(decryptedSignature);
            ByteBuffer buffer = ByteBuffer.allocate(gToX.toByteArray().length + gtoRandomNumber.toByteArray().length);
            buffer.put(gToX.toByteArray()).put(gtoRandomNumber.toByteArray());
            byte[] concat = buffer.array();
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashed = digest.digest(concat);
            if (!Arrays.equals(hashed, decryptedUnsigned)) {
                throw new InvalidSignatureException("Failed to verify the signature!");
            }
            System.out.println("The key exchange was successful!");


        } else {
            throw new InvalidCertificateException("Failed to verify the certificate!");
        }
    }

    private boolean verifyCertificate(Certificate cert) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, cert.getPublicKey());
        byte[] decrypted = cipher.doFinal(cert.getSignature());
        byte[] name = cert.getName().getBytes();
        byte[] publicKey = cert.getPublicKey().getEncoded();
        byte[] g = cert.getG().toByteArray();
        byte[] p = cert.getP().toByteArray();
        ByteBuffer buffer = ByteBuffer.allocate(name.length + publicKey.length + g.length + p.length);
        buffer.put(name).put(publicKey).put(g).put(p);
        byte[] concat = buffer.array();

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashed = digest.digest(concat);

        return Arrays.equals(hashed, decrypted);

    }


    private byte[] sign(byte[] data, PrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        byte[] hashed = messageDigest.digest(data);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return cipher.doFinal(hashed);
    }

    public String getName() {
        return name;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public BigInteger getSharedSecret() {
        return sharedSecret;
    }

    public BigInteger getG() {
        return g;
    }

    public BigInteger getP() {
        return p;
    }

    public BigInteger getGtoRandomNumber() {
        return gtoRandomNumber;
    }

    public int getRandomNumber() {
        return randomNumber;
    }

    public Certificate getCertificate() {
        return certificate;
    }
}
