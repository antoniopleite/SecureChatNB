package Client;

import com.dropbox.core.*;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.stream.JsonReader;
import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.spec.*;
import java.util.Locale;
import java.util.Random;
import java.util.Scanner;
import javax.swing.JFrame;

public class Client {

    private static final String pass1 = "SIO";
    private static String src = "";
    private static String dst = "";
    private static byte[] pKey;
    private static byte[] puKey;

    @SuppressWarnings("empty-statement")
    public static void main(String[] args) throws IOException, DbxException {
        Socket s;
        OutputStream out;
        InputStream in;
        byte[] buffer = new byte[1024];
        int readBytes;
        //Cliente com espera activa, comunicação feita por sockets
        try {
            s = new Socket("localhost", 1111);
            out = s.getOutputStream();
            in = s.getInputStream();
            SecretKey a = register(in, out);

            while (true) {
                int l;
                if (System.in.available() != 0) {
                    l = System.in.read(buffer);
                    byte[] bytesToEncrypt = new byte[l];
                    System.arraycopy(buffer, 0, bytesToEncrypt, 0, l);
                    byte[] encryptedBytes = null;
                    byte[] cipheredMsg = null;
                    if (l == -1) {
                        break;
                    }
                    //encryptedBytes = encryptPassword(bytesToEncrypt);

                    //Cifrar simetricamente, passando a mensagem como argumento
                    //encryptedBytes <--> cipheredMsg
                    cipheredMsg = encryptSymmetric(bytesToEncrypt);
                    //Cifrar chave assimetricamente, passando-a como argumento
                    //cipheredMsg <--> encryptedBytes
                    String encryptedmsg = Base64.encode(cipheredMsg);
                    System.out.println("cipheredMsg --> " + encryptedmsg);
                    encryptedBytes = encryptHybrid(cipheredMsg);
                    String encrypted = Base64.encode(encryptedBytes);
                    System.out.println("encryptedBytes --> " + encrypted);
                    out.write(encryptedBytes, 0, encryptedBytes.length);

                }

                //Recebo do servidor
                if (in.available() != 0) {
                    l = in.read(buffer, 0, buffer.length);
                    byte[] bytesToDecrypt = new byte[l];
                    System.arraycopy(buffer, 0, bytesToDecrypt, 0, l);
                    byte[] decryptedBytes = null;
                    byte[] cipheredMsg = null;
                    //Falta ter acesso ao json com o tipo de decifra a fazer
                    //decryptedBytes = decryptPassword(bytesToDecrypt);
                    System.out.println(Base64.encode(buffer));
                    System.out.println("Aqui");
                    cipheredMsg = decryptHybrid(bytesToDecrypt);
                    System.out.println("Ja chego");
                    decryptedBytes = decryptSymmetric(cipheredMsg);
                    System.out.println("Acabou");
                    JsonReader jr = new JsonReader(new InputStreamReader(new ByteArrayInputStream(decryptedBytes), "UTF-8"));
                    JsonParser parser = new JsonParser();
                    JsonElement data = parser.parse(jr);
                    JsonObject cmd = data.getAsJsonObject();
                    cmd.remove("iv");

                    decryptedBytes = cmd.toString().getBytes();
                    System.out.write(decryptedBytes, 0, decryptedBytes.length);
                    System.out.print("\n");
                }
                Thread.currentThread().sleep(200); // 100 milis
            }
        } catch (Exception e) {
            System.err.println("Exception: " + e);
        }
    }

    private static void dropbox(String opt) throws IOException, DbxException {
        //Api Dropbox para guardar ficheiros das public keys
        final String APP_KEY = "9vbj3zxu7k908vu";
        final String APP_SECRET = "f4cgben9h934p3v";
        DbxAppInfo appInfo = new DbxAppInfo(APP_KEY, APP_SECRET);
        DbxRequestConfig config = new DbxRequestConfig("JavaTutorial/1.0", Locale.getDefault().toString());
        DbxWebAuthNoRedirect webAuth = new DbxWebAuthNoRedirect(config, appInfo);
        String authorizeUrl = webAuth.start();
        System.out.println("1. Go to: " + authorizeUrl);
        System.out.println("2. Click \"Allow\" (you might have to log in first)");
        System.out.println("3. Copy the authorization code.");
        String code = new BufferedReader(new InputStreamReader(System.in)).readLine().trim();
        DbxAuthFinish authFinish = webAuth.finish(code);
        String accessToken = authFinish.accessToken;
        DbxClient client = new DbxClient(config, accessToken);
        System.out.println("Linked account: " + client.getAccountInfo().displayName);
        if (opt.equals("upload")) {
            //Upload de um ficheiro para a dropbox
            File inputFile = new File("pubkey" + src);
            FileInputStream inputStream = new FileInputStream(inputFile);
            try {
                DbxEntry.File uploadedFile = client.uploadFile("/pubkey" + src,
                        DbxWriteMode.add(), inputFile.length(), inputStream);
                System.out.println("Uploaded: " + uploadedFile.toString());
            } finally {
                inputStream.close();
            }
        } else if (opt.equals("download")) {
            //Download de um ficheiro da dropbox
            FileOutputStream outputStream = new FileOutputStream("pubkey" + dst);
            try {
                DbxEntry.File downloadedFile = client.getFile("/pubkey" + dst, null,
                        outputStream);
                System.out.println("Metadata: " + downloadedFile.toString());
            } finally {
                outputStream.close();
            }
        }
    }

    private static SecretKey register(InputStream in, OutputStream out) throws IOException {
        byte[] buffer = new byte[1024];
        SecretKey secret = null;
        Scanner sc = new Scanner(System.in);
        System.out.print("Nome a registar: ");
        String nome = sc.next();
        JsonObject js = new JsonObject();
        js.addProperty("command", "register");
        js.addProperty("src", nome);
        byte[] bt = js.toString().getBytes();
        //  System.arraycopy(bt, 0, buffer, 0, bt.length);
        out.write(bt, 0, bt.length);
        while (true) {
            int l;
            //Recebo do servidor
            if (in.available() != 0) {
                l = in.read(buffer, 0, buffer.length);
                System.out.write(buffer, 0, l);
                System.out.print("\n");
                JsonReader jr = new JsonReader(new InputStreamReader(new ByteArrayInputStream(buffer), "UTF-8"));
                JsonParser parser = new JsonParser();
                JsonObject data = parser.parse(jr).getAsJsonObject();
                if (data.get("error").getAsString().equals("ok")) {
                    src = nome;
                    try {
                        secret = generateKeyPair();
                        dropbox("upload");
                    } catch (NoSuchAlgorithmException | DbxException e) {
                        e.printStackTrace();
                    }
                    break;
                } else {
                    register(in, out);
                }
            }
        }
        return secret;
    }

    private static SecretKey generateKeyPair() throws NoSuchAlgorithmException, IOException {
        //Generate assymmetric key
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.genKeyPair();
        PrivateKey privKey = keyPair.getPrivate();
        PublicKey pubKey = keyPair.getPublic();
        pKey = privKey.getEncoded();

        //Generate symmetric key
        KeyGenerator aesKeyGenerator = KeyGenerator.getInstance("AES");
        SecureRandom random = new SecureRandom();
        aesKeyGenerator.init(random);
        SecretKey aesSecretKey = aesKeyGenerator.generateKey();

        FileOutputStream fos = new FileOutputStream("pubkey" + src);
        byte[] puKey = pubKey.getEncoded();
        fos.write(puKey);
        fos.close();
        return aesSecretKey;
    }

    private static byte[] encryptPassword(byte[] b) throws UnsupportedEncodingException, UnsupportedOperationException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidParameterSpecException, ProviderException, InvalidAlgorithmParameterException {

        JsonReader jr = new JsonReader(new InputStreamReader(new ByteArrayInputStream(b), "UTF-8"));
        JsonParser parser = new JsonParser();
        JsonElement data = parser.parse(jr);
        byte[] bt = null;

        if (data.isJsonObject()) {

            JsonObject json = data.getAsJsonObject();

            if (json.has("msg")) {

                JsonElement cmd = json.get("msg");
                String msg = cmd.getAsString();
                cmd = json.get("dst");
                dst = cmd.getAsString();

                Random r = new SecureRandom();
                byte[] salt = new byte[20];
                r.nextBytes(salt);
                char[] password = pass1.toCharArray();

                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                KeySpec spec = new PBEKeySpec(password, salt, 65536, 128);
                SecretKey tmp = factory.generateSecret(spec);
                SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");

                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, secret);
                AlgorithmParameters params = cipher.getParameters();
                byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();
                byte[] ciphertext = cipher.doFinal(msg.getBytes("UTF-8"));
                byte[] secretArray = secret.getEncoded();

                //encriptação da chave
                //byte[] b = encryptPwd(secretArray);
                String saltBase64 = Base64.encode(salt);
                String cipherBase64 = Base64.encode(ciphertext);
                String secretBase64 = Base64.encode(secretArray);
                String ivBase64 = Base64.encode(iv);
                json.remove("msg");
                json.addProperty("msg", cipherBase64);
                json.addProperty("key", secretBase64);
                json.addProperty("iv", ivBase64);
                json.addProperty("salt", saltBase64);
                json.addProperty("type", 0);
                bt = json.toString().getBytes();
                return bt;
            }
        }
        return b;
    }

    private static byte[] decryptPassword(byte[] b) throws UnsupportedEncodingException, UnsupportedOperationException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidParameterSpecException, ProviderException, InvalidAlgorithmParameterException {

        JsonReader jr = new JsonReader(new InputStreamReader(new ByteArrayInputStream(b), "UTF-8"));
        JsonParser parser = new JsonParser();
        JsonElement data = parser.parse(jr);
        byte[] bt = null;

        if (data.isJsonObject()) {
            JsonObject json = data.getAsJsonObject();
            if (json.has("msg")) {
                JsonElement cmd = json.get("msg");
                String msg = cmd.getAsString();
                cmd = json.get("iv");

                String iv = cmd.getAsString();
                cmd = json.get("salt");
                String saltEnc = cmd.getAsString();
                byte[] saltDec = Base64.decode(saltEnc);
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                char[] password = pass1.toCharArray();
                KeySpec spec = new PBEKeySpec(password, saltDec, 65536, 128);
                SecretKey tmp = factory.generateSecret(spec);
                SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");

//                SecretKeySpec sks = new SecretKeySpec(Base64.decode(secret), "AES");
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(Base64.decode(iv)));
                String plaintext = new String(cipher.doFinal(Base64.decode(msg)), "UTF-8");
                json.remove("msg");
                json.addProperty("msg", plaintext);
                bt = json.toString().getBytes();
                return bt;
            }
        }
        return b;
    }

    private static byte[] encryptSymmetric(byte b[]) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidParameterSpecException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
        JsonReader jr = new JsonReader(new InputStreamReader(new ByteArrayInputStream(b), "UTF-8"));
        JsonParser parser = new JsonParser();
        JsonElement data = parser.parse(jr);
        byte[] bt = null;
        byte[] secretArray = null;
        byte[] ciphertext = null;
        if (data.isJsonObject()) {
            JsonObject json = data.getAsJsonObject();
            if (json.has("msg")) {

                //Tratamento dos dados json
                JsonElement cmd = json.get("msg");
                String msg = cmd.getAsString();

                //Cifra simetrica
                Key secret = KeyGenerator.getInstance("AES").generateKey();
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, secret);
                AlgorithmParameters params = cipher.getParameters();
                byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();
                ciphertext = cipher.doFinal(msg.getBytes("UTF-8"));

                //Preenchimento do JsonObject
                secretArray = secret.getEncoded();
                String secretString = Base64.encode(secretArray);
                String ivString = Base64.encode(iv);
                String msgString = Base64.encode(ciphertext);
                json.addProperty("iv", ivString);
                json.addProperty("key", secretString);
                json.addProperty("msg", msgString);
                bt = json.toString().getBytes();

                return bt;
            }
        }
        return b;
    }

    private static byte[] decryptSymmetric(byte[] b) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        JsonReader jr = new JsonReader(new InputStreamReader(new ByteArrayInputStream(b), "UTF-8"));
        JsonParser parser = new JsonParser();
        JsonElement data = parser.parse(jr);
        byte[] bt = null;

        if (data.isJsonObject()) {
            JsonObject json = data.getAsJsonObject();
            if (json.has("msg")) {
                
                //Tratamento do objecto Json
                JsonElement cmd = json.get("msg");
                String msgString = cmd.getAsString();
                byte[] msg = Base64.decode(msgString);
                cmd = json.get("iv");
                String ivString = cmd.getAsString();
                byte[] iv = Base64.decode(ivString);
                cmd = json.get("key");

                //Preenchimento do JsonObject
                String secretString = cmd.getAsString();
                byte[] secretArray = Base64.decode(secretString);
                SecretKey secret = new SecretKeySpec(secretArray, 0, secretArray.length, "AES");
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(iv));
                String plaintext = new String(cipher.doFinal(msg));
                json.remove("msg");
                json.addProperty("msg", plaintext);
                bt = json.toString().getBytes();

                return bt;
            }
        }
        return b;
    }

    private static byte[] encryptHybrid(byte[] b) throws IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, InvalidKeyException, FileNotFoundException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException {
        //ir a dropbox buscar a public key

        JsonReader jr = new JsonReader(new InputStreamReader(new ByteArrayInputStream(b), "UTF-8"));
        JsonParser parser = new JsonParser();
        JsonElement data = parser.parse(jr);
        byte[] bt = null;
        if (data.isJsonObject()) {
            JsonObject json = data.getAsJsonObject();
            if (json.has("msg")) {

                //Tratamento do objecto Json
                JsonElement cmd = json.get("key");
                String keyString = cmd.getAsString();
                cmd = json.get("dst");
                dst = cmd.getAsString();
                byte[] key = Base64.decode(keyString);
                FileInputStream fis = new FileInputStream("pubkey" + dst);
                byte[] f = new byte[fis.available()];
                fis.read(f);
                fis.close();
                KeyFactory kf = KeyFactory.getInstance("RSA");
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(f);
                PublicKey pubK = kf.generatePublic(keySpec);
                Cipher cipher = Cipher.getInstance("RSA");
                cipher.init(Cipher.ENCRYPT_MODE, pubK);

                byte[] cipheredKey = cipher.doFinal(key);
                String cipheredkeyString = Base64.encode(cipheredKey);
                json.remove("key");
                json.addProperty("key", cipheredkeyString);

                bt = json.toString().getBytes();
                return bt;
            }
            try {
                dropbox("download");
            } catch (IOException | DbxException e) {
                e.printStackTrace();
            }
        }
        return b;
    }

    private static byte[] decryptHybrid(byte[] b) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        JsonReader jr = new JsonReader(new InputStreamReader(new ByteArrayInputStream(b), "UTF-8"));
        JsonParser parser = new JsonParser();
        JsonElement data = parser.parse(jr);
        byte[] bt = null;
        if (data.isJsonObject()) {
            JsonObject json = data.getAsJsonObject();
            if (json.has("msg")) {
                JsonElement cmd = json.get("key");
                String keyString = cmd.getAsString();
                byte[] key = Base64.decode(keyString);
//                byte[] tempSecret = new byte[256];
//                System.arraycopy(b, 0, tempSecret, 0, b.length);
                KeyFactory kf = KeyFactory.getInstance("RSA");
                PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pKey);
                PrivateKey pk = kf.generatePrivate(spec);
                Cipher cifra = Cipher.getInstance("RSA");
                cifra.init(Cipher.DECRYPT_MODE, pk);
                byte[] decipheredKey = cifra.doFinal(key);
                keyString = Base64.encode(decipheredKey);
                json.remove("key");
                json.addProperty("key", keyString);
                bt = json.toString().getBytes();
                return bt;
            }
        }
        return null;
    }
}
