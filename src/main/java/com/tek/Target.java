package com.tek;

public class Target {

    public static void main(String[] args) {
        Target target = new Target();
        target.run();
    }

    private void run(){
        JJWT jjwt = new JJWT();

        try {
            String jwe = jjwt.senderSignAndEncrypt();
            System.out.println(jwe);
        }
        catch(Exception ex){
            System.out.println(ex.getMessage());
        }
    }



}
