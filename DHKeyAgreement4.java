import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;

 public class DHKeyAgreement4{
 private DHKeyAgreement4() {}
 public static void main(String argv[]) throws Exception {
 // Alice key generation
 KeyPairGenerator aliceKpairGen = KeyPairGenerator.getInstance("DH");
 aliceKpairGen.initialize(2048); //parameters
 KeyPair aliceKpair = aliceKpairGen.generateKeyPair();
 DHParameterSpec dhParamShared =
((DHPublicKey)aliceKpair.getPublic()).getParams();
 // Bob key generation
 KeyPairGenerator bobKpairGen = KeyPairGenerator.getInstance("DH");
 bobKpairGen.initialize(dhParamShared);
 KeyPair bobKpair = bobKpairGen.generateKeyPair();
 // Carol key generation
 KeyPairGenerator carolKpairGen = KeyPairGenerator.getInstance("DH");
 carolKpairGen.initialize(dhParamShared);
 KeyPair carolKpair = carolKpairGen.generateKeyPair();
 // Derek key generation
 KeyPairGenerator derekKpairGen = KeyPairGenerator.getInstance("DH");
 derekKpairGen.initialize(dhParamShared);
 KeyPair derekKpair = derekKpairGen.generateKeyPair();
 //Alice initialize
 KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("DH");
 //Alice computes key A
 aliceKeyAgree.init(aliceKpair.getPrivate());
 //Bob initialize
 KeyAgreement bobKeyAgree = KeyAgreement.getInstance("DH");
 //Bob computes key B
 bobKeyAgree.init(bobKpair.getPrivate());
 //Carol initialize
 KeyAgreement carolKeyAgree = KeyAgreement.getInstance("DH");
 //Carol computes key C
 carolKeyAgree.init(carolKpair.getPrivate());
 //Derek initialize
 KeyAgreement derekKeyAgree = KeyAgreement.getInstance("DH");
 //Derek computes key D
 derekKeyAgree.init(derekKpair.getPrivate());
 //Alice- key DA
 Key DA = aliceKeyAgree.doPhase(derekKpair.getPublic(), false);
 //Bob- key AB
 Key AB = bobKeyAgree.doPhase(aliceKpair.getPublic(), false);
 //Carol- key BC
 Key BC = carolKeyAgree.doPhase(bobKpair.getPublic(), false);
 //Derek- key CD
 Key CD = derekKeyAgree.doPhase(carolKpair.getPublic(), false);
 //Alice- key CDA
 Key CDA = aliceKeyAgree.doPhase(CD, false);
 //Bob- key DAB
 Key DAB = bobKeyAgree.doPhase(DA, false);
 //Carol- key ABC
 Key ABC = carolKeyAgree.doPhase(AB, false);
 //Derek- key BCD
 Key BCD = derekKeyAgree.doPhase(BC, false);
 //Secret key generation:
 //Alice- key BCSA
 Key aSecret = aliceKeyAgree.doPhase(BCD, true);
 //Bob- key CSAB
 Key bSecret = bobKeyAgree.doPhase(CDA, true);
 //Carol- key SABC
 Key cSecret = carolKeyAgree.doPhase(DAB, true);
 //Derek- key ABCS
 Key dSecret = derekKeyAgree.doPhase(ABC, true);
 // Compute Secret Key
 byte[] aliceSharedSecret = aliceKeyAgree.generateSecret();
 System.out.println("Alice secret: " + toHexString(aliceSharedSecret));
 byte[] bobSharedSecret = bobKeyAgree.generateSecret();
 System.out.println("Bob secret: " + toHexString(bobSharedSecret));
 byte[] carolSharedSecret = carolKeyAgree.generateSecret();
 System.out.println("Carol secret: " + toHexString(carolSharedSecret));
 byte[] derekSharedSecret = derekKeyAgree.generateSecret();
 System.out.println("derek secret: " + toHexString(derekSharedSecret));
 // Compare AB
 if (!java.util.Arrays.equals(bobSharedSecret, aliceSharedSecret))
 {
 System.out.println("Alice and Bob are different");
 }
 else
 {
 System.out.println("Alice and Bob are same");
 }
 // Compare BC
 if (!java.util.Arrays.equals(carolSharedSecret, bobSharedSecret))
 {
 System.out.println("Bob and Carol are different");
 }
 else
 {
 System.out.println("Bob and Carol are same");
 }
 //Compare CD
 if (!java.util.Arrays.equals(derekSharedSecret, carolSharedSecret))
 {
 System.out.println("Carol and Derek are different");
 }
 else
 {
 System.out.println("Carol and Derek are same");
 }
 }
 //Provided function-
 private static void byte2hex(byte b, StringBuffer buf) {
 char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
 '9', 'A', 'B', 'C', 'D', 'E', 'F' };
 int high = ((b & 0xf0) >> 4);
 int low = (b & 0x0f);
 buf.append(hexChars[high]);
 buf.append(hexChars[low]);
 }
 //Provided function-
 private static String toHexString(byte[] block) {
 StringBuffer buf = new StringBuffer();
 int len = block.length;
 for (int i = 0; i < len; i++) {
 byte2hex(block[i], buf);
 if (i < len-1) {
 buf.append(":");
 }
 }
 return buf.toString();
 }
 }