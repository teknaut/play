package com.tek;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONObject;

import java.security.SecureRandom;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class JJWT {

    protected void generateAndVerifyJWS() throws Exception {

        // Create an HMAC-protected JWS object with some payload
        JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS256),
                new Payload(getJson()));

        // We need a 256-bit key for HS256 which must be pre-shared
        byte[] sharedKey = new byte[32];
        new SecureRandom().nextBytes(sharedKey);

        // Apply the HMAC to the JWS object
        jwsObject.sign(new MACSigner(sharedKey));

        // Output in URL-safe format
        String JWS = jwsObject.serialize();

        try {
            jwsObject = JWSObject.parse(JWS);
        } catch (java.text.ParseException e) {
            // Invalid JWS object encoding
        }

        JWSVerifier verifier = new MACVerifier(sharedKey);

        // continue with signature verification...
        if (jwsObject.verify(verifier)) {
            System.out.println("verified OK");
        }

        System.out.println(jwsObject.getPayload().toString());
    }

    private static String getJson() {
        Map<String, String> deets = new HashMap();
        deets.put("key1", "val1");
        deets.put("key2", "val2");
        return JSONObject.toJSONString(deets);
    }

    private RSAKey generateRecipientKeys() throws JOSEException {
        RSAKey senderJWK = new RSAKeyGenerator(2048)
                .keyID("123")
                .keyUse(KeyUse.SIGNATURE)
                .generate();
        return senderJWK;
    }

    private RSAKey generateSenderKeys() throws Exception {
        RSAKey recipientJWK = new RSAKeyGenerator(2048)
                .keyID("456")
                .keyUse(KeyUse.ENCRYPTION)
                .generate();
        return recipientJWK;
    }

    protected String senderSignAndEncrypt() throws Exception {

        RSAKey senderJWK = generateSenderKeys();

        RSAKey recipientJWK = generateRecipientKeys();

        // Create JWT
        SignedJWT signedJWT = new SignedJWT(

            new JWSHeader.
                    Builder(JWSAlgorithm.RS256).
                    keyID(senderJWK.getKeyID()).build(),

            new JWTClaimsSet.Builder()
                    .subject("alice")
                    .issueTime(new Date())
                    .issuer("https://c2id.com")
                    .build()
        );

        // Sign the JWT
        signedJWT.sign(new RSASSASigner(senderJWK));

        // Create JWE object with signed JWT as payload
        JWEObject jweObject = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                        .contentType("JWT") // required to indicate nested JWT
                        .build(),
                new Payload(signedJWT));

        // Encrypt with the recipient's public key
        jweObject.encrypt(new RSAEncrypter(recipientJWK));

        // Serialise to JWE compact form
        String jweString = jweObject.serialize();

        return jweString;
    }
}
