package com.tek;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;

import java.security.SecureRandom;
import java.util.Base64;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;

public class JWS {


    public void showMe() throws Exception{


        // Generate random 256-bit (32-byte) shared secret
        SecureRandom random = new SecureRandom();
        byte[] realSecret = new byte[32];
        random.nextBytes(realSecret);

        String secret = Base64.getEncoder().encodeToString(realSecret);





        byte[] decodedSecret = secret.getBytes();

// Create HMAC signer
        JWSSigner signer = new MACSigner(decodedSecret);

// Prepare JWS object with "Hello, world!" payload
        JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS256), new Payload("Hello, world!"));

// Apply the HMAC
        jwsObject.sign(signer);

// To serialize to compact form, produces something like
// eyJhbGciOiJIUzI1NiJ9.SGVsbG8sIHdvcmxkIQ.onO9Ihudz3WkiauDO2Uhyuz0Y18UASXlSc1eS0NkWyA
        String s = jwsObject.serialize();

        System.out.println(s);

// To parse the JWS and verify it, e.g. on client-side
        jwsObject = JWSObject.parse(s);

        JWSVerifier verifier = new MACVerifier(decodedSecret);

        assertTrue(jwsObject.verify(verifier));

        assertEquals("Hello, world!", jwsObject.getPayload().toString());

    }


}
