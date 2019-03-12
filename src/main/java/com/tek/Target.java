package com.tek;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import net.minidev.json.JSONObject;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

public class Target {

    public static void main(String[] args) throws Exception{
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
        if(jwsObject.verify(verifier)){
            System.out.println("verified OK");
        }

        System.out.println(jwsObject.getPayload().toString());
    }

    private static String getJson(){
        Map<String, String> deets = new HashMap();
        deets.put("key1", "val1");
        deets.put("key2", "val2");
        return JSONObject.toJSONString(deets);
    }

}
