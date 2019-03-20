package com.tek;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static org.junit.Assert.assertEquals;

public class JWE {

    public SecretKey getKey() throws NoSuchAlgorithmException {
        // Generate symmetric 128 bit AES key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        return keyGen.generateKey();
    }

    public void allCode() throws Exception {

        SecretKey key = getKey();
//        String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());
//
//
//        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
//
//
//// rebuild key using SecretKeySpec
//        SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");


// Create the header
        JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128GCM);

// Set the plain text
        Payload payload = new Payload("Hello world!");

// Create the JWE object and encrypt it
        JWEObject jweObject = new JWEObject(header, payload);
        jweObject.encrypt(new DirectEncrypter(key));

// Serialise to compact JOSE form...
        String jweString = jweObject.serialize();

// Parse into JWE object again...
        jweObject = JWEObject.parse(jweString);

        System.out.println(jweString);

// Decrypt
        jweObject.decrypt(new DirectDecrypter(key));

// Get the plain text
        payload = jweObject.getPayload();
        assertEquals("Hello world!", payload.toString());

    }
}
