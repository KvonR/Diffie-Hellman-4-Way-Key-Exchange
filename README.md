# Message Authentication & Key Exchange

### K Rahimi - 29/03/2023

---

## Abstract

Message Authentication & Key Exchange are crucial components to a secure network communication. Message authentication makes sure the content of your message is not altered (keeping integrity). Key exchange allows for secure communication using a shared secret key. In this report, I examine various message authenticaton techniques such as Hash Functions, DSA and RSA+SHA1 and explore their advantages & disadvatages. Additionally, implemention of a Four-Party Diffie-Hellman Key Exchange Protocol theoretical design, then later, an actual java implementation is used. Ultimately, this report is to provide a summary of the various types of message authentication & explores the expansion of Diffie-Hellman Key Exchange.

---

## Content

1. Comparison of methods for message authentication:
    1. Aspects of message authentication
    2. Hash Functions
    3. RSA+SHA1
    4. DSA
    5. HMAC+SHA256
2. Key Exchange for Four Parties
    1. Theoretical Design of Diffie-Hellman with Four Parties
    2. Implementation of 4-Party Diffie Hellman Protocol
3. References

---

## **Comparison of methods for message authentication**

### Aspects of message authentication

It must be ensured that:

- Content of message not been altered (integrity);
- Source can be proved to reciever (authenticity);
- Source can be proven to a third-party (non-repudiation).

The Integrity, Authentication and Non-Repudation of Hash Functions, RSA+SHA, DSA and HMAC can be summarised in this table:

|  | Integrity | Authentication | Non-Repudiation |
| --- | --- | --- | --- |
| Hash Functions | ✅ | ❌ | ❌ |
| RSA+SHA-1 | ✅ | ✅ | ✅ |
| DSA | ✅ | ✅ | ✅ |
| HMAC | ✅ | ✅ | ❌ |

### Hash Functions

Hash functions take an arbitrary input and outputs a fixed size hash-value. The purpose of this is to provide integrity by ensuring the message has not been altered when transmitted.

**Advantages:**

- Difficult to tamper with message as small changes result in different hash value;
- Efficient computation of hash values;
- Well-defined standard, therefore, it is widely used.

**Disadvantages:**

- It is difficult to retrieve the original message from the hash value as Hash Functions are one-way functions. (This could be advantageous as well);
- Hash function do not provide authentication nor Non-Repudation.

### RSA + SHA1

RSA is a public-key encryption algorithm(uses a public and private key).

SHA-1  hashes the message before applying RSA.

This method provides us with integrity, authentication and non-repudation.

**Advantages:**

- SHA-1 provides integrity while RSA ensures secure exchange of keys;
- Well-defined standard, therefore, it is widely used.

**Disadvantages:**

- RSA is computationally expensive, especially with bigger inputs;
- SHA-1 has been replaced by newer hash functions as it is considered to not be as secure.

### DSA

DSA is a public-key algorithm (uses public and private keys). It can be useful for digital signatures. 

It uses a random number generator to generate the signature, which is verified using the reciepient’s public key.

It provides us with message integrity authentication and non-repudation.

**Advantages:**

- DSA is a widely used standard;
- DSA strongly guarantees integrity,authentication and non-repudation.

**Disadvantages:**

- DSA’s random number generator can introduce vulnerabilities if not  handled correctly;
- DSA is computationally expensive, especially when provided with bigger inputs.

### HMAC+SHA-256

HMAC-SHA256 is a MAC(message authentication code) that combines a hash function(SHA-256) with a private key. This provides us with integrity & authentication.

HMAC-SHA256 is used in network protocols.

**Advantages:**

- HMAC-SHA256 strongly guarantees integrity and authentication;
- The private-key gives an extra layer of security.

**Disadvantages:**

- It doesn’t give us Non-Repudiation;
- This method’s strength comes from the secrecy of the private key. If someone gets this key, they have access to the entire system.

---

## Key Exchange for Four Parties

### Theoretical Design of Diffie-Hellman with Four Parties

1. All four senders(Alice, Bob, Carol, Derek) agree on a common modulus p and a generator g.
2. Each sender generates a private key, x{A}, x{B}, x{C}, and x{D}.
3. Each sender calculates a public key: y{A} = g^(x{A}) mod p, y{B} = g^(x{B}) mod p, y{C} = g^(x{C}) mod p, and y{D} = g^(x{D}) mod p.
4. Each sender sends their public key to all other senders.
5. Each sender calculates the same shared secret key as follows:
a. Alice calculates K{AB} = y{B}^(x{A}) mod p, K{AB} = y{C}^(x{A}) mod p, and K{AD} = y{D}^(x) mod p.
b. Bob calculates K{BA} = y{A}^(x{B}) mod p, K{BC} = y{C}^(x{B}) mod p, and K{BD} = y{D}^(x{B}) mod p.
c. Carol calculates K{CA} = y{A}^(x{C}) mod p, K{CB} = y{B}^(x{C}) mod p, and K{CD} = y{D}^(x{C}) mod p.
d. Derek calculates K{DA} = y{A}^(x{D}) mod p, K{DB} = y{B}^(x{D}) mod p, and K{DC} = y{C}^(x{D}) mod p.
6. Each party now has a shared secret key with every other party.

As you can see, we extend 3-party Diffie-Hellman protocol to 4-party DH protocol using another round of communication to calculate the secret key.

### Implementation of 4-Party Diffie Hellman Protocol

Implementation:

```r
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
            DHParameterSpec dhParamShared = ((DHPublicKey)aliceKpair.getPublic()).getParams();
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
```

Implementing 4-party from 3-party requires an extra iteration of communication.

The code uses Alice to set the key parameters such as the key size(Set:2048). Bob, Carol and Derek use these parameters to set up their own key pairs.

The output the code produces is as follows:

![Screenshot 2023-03-31 at 11.44.07.png](Message%20Authentication%20&%20Key%20Exchange%20f30ef006a0704fdd95419b2b74ffd7e7/Screenshot_2023-03-31_at_11.44.07.png)

There is assurance that the private key is correct as the last lines of output tell the user whether the keys are the same or whether they are different.

---

## References

Alexei Lisitsa,(2023), **LAB 4-5 https://www.csc.liv.ac.uk/~alexei/COMP232_20/COMP232_LAB_4-5_20.pdf** (Accessed: 29st March 2023) - Message authentication techniques

Alexei Lisitsa,(2023), **LAB 8     https://www.csc.liv.ac.uk/~alexei/COMP232_20/COMP232_LAB_8_20.pdf**(Accessed: 29st March 2023) - Message authentication techniques

Alexei Lisitsa,(2023),**Diffie-Hellman 3-Party Key Exchange https://www.csc.liv.ac.uk/~alexei/COMP232/DHKeyAgreement3.java** (Accessed: 29st March 2023) - Algorithm that the code was based on
