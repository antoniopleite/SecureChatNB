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

class Client {

    private static final String pass = "SIO";
    private static String src = "";
    private static String dst = "";
    private static byte[] pKey;
    private static byte[] puKey;


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

/*
            try
            {
                do
                {
                    readBytes = in.read(buffer);
                    if (readBytes > 0)
                    {
                        byte[] bytesToEncrypt = new byte[readBytes];
                        System.arraycopy(buffer, 0, bytesToEncrypt, 0, readBytes);
                        boolean last = false;
                        if (readBytes < 1024)
                            last = true;
                        byte [] encripted = keymanager.encryptBytes(bytesToEncrypt, chaveDeposito, Algoritmos.getALG_SYM(),last);
                    }
                }
                while (readBytes > 0);
            }
            finally
            {
                in.close();
            }*/

            register(in, out);

            while (true) {
                int l;
                if (System.in.available() != 0) {
                    l = System.in.read(buffer);
                    byte[] bytesToEncrypt = new byte[l];
                    System.arraycopy(buffer, 0, bytesToEncrypt, 0, l);
                    byte[] encryptedBytes = null;
                    if (l == -1) break;
                    try {
                        encryptedBytes = encryptMsg(bytesToEncrypt);
                    } catch (UnsupportedEncodingException | UnsupportedOperationException | InvalidKeySpecException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | InvalidParameterSpecException | ProviderException e) {
                        e.printStackTrace();
                    }

                    out.write(encryptedBytes, 0, encryptedBytes.length);

                }

                //Recebo do servidor
                if (in.available() != 0) {
                    l = in.read(buffer, 0, buffer.length);
                    byte[] bytesToDecrypt = new byte[l];
                    System.arraycopy(buffer, 0, bytesToDecrypt, 0, l);
                    byte[] decryptedBytes = null;
                    decryptedBytes = decryptMsg(bytesToDecrypt);
                    /*byte[] bytesToDencrypt = new byte[l];
                    System.arraycopy(bytesToDencrypt, 0, buffer, 0, l);
                    byte[] decryptedBytes = null;
                    try {
                        decryptedBytes = decryptMsg(bytesToDencrypt, secret);
                    }catch (UnsupportedEncodingException | UnsupportedOperationException | InvalidKeySpecException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | InvalidParameterSpecException | ProviderException e) {
                        e.printStackTrace();
                    }*/

                    System.out.write(decryptedBytes, 0, decryptedBytes.length);
                    System.out.print("\n");
                }

                Thread.currentThread().sleep(200); // 100 milis
            }
        } catch (Exception e) {
            System.err.println("Exception: " + e);
        }
    }


    private static byte[] encryptMsg(byte[] buff) throws UnsupportedEncodingException, UnsupportedOperationException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidParameterSpecException, ProviderException, InvalidAlgorithmParameterException {

        JsonReader jr = new JsonReader(new InputStreamReader(new ByteArrayInputStream(buff), "UTF-8"));
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
                char[] password = pass.toCharArray();


                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

                KeySpec spec = new PBEKeySpec(password, salt, 65536, 128);
                SecretKey tmp = factory.generateSecret(spec);
                SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");
//                byte[] iv = new byte[16];
//                new Random().nextBytes(iv);
//                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, secret);
                AlgorithmParameters params = cipher.getParameters();
                byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();
                byte[] ciphertext = cipher.doFinal(msg.getBytes("UTF-8"));
                byte[] secretArray = secret.getEncoded();
                //encriptação da chave
                byte[] b = encryptPwd(secretArray);

                String cipherBase64 = Base64.encode(ciphertext);
                String secretBase64 = Base64.encode(b);
                String ivBase64 = Base64.encode(iv);

                json.remove("msg");
                json.addProperty("msg", cipherBase64);
                json.addProperty("key", secretBase64);
                json.addProperty("iv", ivBase64);
                bt = json.toString().getBytes();
                return bt;
            }
        }
        return buff;
    }

    private static byte[] decryptMsg(byte[] dados) throws UnsupportedEncodingException, UnsupportedOperationException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidParameterSpecException, ProviderException, InvalidAlgorithmParameterException {

        JsonReader jr = new JsonReader(new InputStreamReader(new ByteArrayInputStream(dados), "UTF-8"));
        JsonParser parser = new JsonParser();
        JsonElement data = parser.parse(jr);
        byte[] bt = null;

        if (data.isJsonObject()) {

            JsonObject json = data.getAsJsonObject();

            if (json.has("msg")) {

                JsonElement cmd = json.get("msg");
                String msg = cmd.getAsString();

                cmd = json.get("key");
                String secret = cmd.getAsString();

                byte[] sk = decryptPwd(Base64.decode(secret));

                cmd = json.get("iv");
                String iv = cmd.getAsString();

                SecretKeySpec sks = new SecretKeySpec(sk, "AES");

                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, sks, new IvParameterSpec(Base64.decode(iv)));
                String plaintext = new String(cipher.doFinal(Base64.decode(msg)), "UTF-8");

                json.remove("msg");
                json.addProperty("msg", plaintext);

                bt = json.toString().getBytes();
                return bt;

            }
        }
        return dados;
    }

    private static void dropbox(String opt) throws IOException, DbxException {
        //Api Dropbox para guardar ficheiros das public keys

        final String APP_KEY = "9vbj3zxu7k908vu";
        final String APP_SECRET = "f4cgben9h934p3v";

        DbxAppInfo appInfo = new DbxAppInfo(APP_KEY, APP_SECRET);

        DbxRequestConfig config = new DbxRequestConfig(
                "JavaTutorial/1.0", Locale.getDefault().toString());
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

    private static void register(InputStream in, OutputStream out) throws IOException {
        byte[] buffer = new byte[1024];

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
                        generetaKeyPair();
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
    }

    private static void generetaKeyPair() throws NoSuchAlgorithmException, IOException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.genKeyPair();
        PrivateKey privKey = keyPair.getPrivate();
        PublicKey pubKey = keyPair.getPublic();
        pKey = privKey.getEncoded();

        FileOutputStream fos = new FileOutputStream("pubkey" + src);
        byte[] puKey = pubKey.getEncoded();
        fos.write(puKey);
        fos.close();
    }

    private static byte[] encryptPwd(byte[] b) {
        //ir a dropbox buscar a public key
        try {
            dropbox("download");
        } catch (IOException | DbxException e) {
            e.printStackTrace();
        }

        try {

            FileInputStream fis = new FileInputStream("pubkey" + dst);
            byte[] f = new byte[fis.available()];
            fis.read(f);
            fis.close();

            KeyFactory kf = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(f);
            PublicKey pubK = kf.generatePublic(keySpec);
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, pubK);
            byte[] criptogram = cipher.doFinal(b);
            return criptogram;
        } catch (InvalidKeySpecException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static byte[] decryptPwd(byte[] b) {
        try {
            byte[] tempSecret = new byte[256];
            System.arraycopy(b,0,tempSecret,0,b.length);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pKey);
            PrivateKey pk = kf.generatePrivate(spec);
            Cipher cifra = Cipher.getInstance("RSA");
            cifra.init(Cipher.DECRYPT_MODE, pk);
            return cifra.doFinal(tempSecret);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeySpecException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;
    }
}
