package com.tek;

import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class Target {

    public static void main(String[] args) {
        Target target = new Target();
        target.run();
    }

    private void run(){
        JJWT jjwt = new JJWT();

        try {
            RSAKey senderJWK = jjwt.generateSenderKeys();

            RSAKey recipientJWK = jjwt.generateRecipientKeys();

            String jwe = jjwt.senderSignAndEncrypt(senderJWK, recipientJWK);
            System.out.println(jwe);

            //now lets decrypt the JWE and verify the signature
            jjwt.consumeEncryptedJWE(jwe, senderJWK, recipientJWK);
        }
        catch(Exception ex){
            System.out.println(ex.getMessage());
        }
    }



}
