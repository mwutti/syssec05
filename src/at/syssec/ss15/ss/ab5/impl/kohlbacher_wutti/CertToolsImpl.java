package at.syssec.ss15.ss.ab5.impl.kohlbacher_wutti;

import at.syssec.ss15.ss.ab5.CertTools;

import javax.net.ssl.HttpsURLConnection;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.*;

/**
 * KeyUsage ::= BIT STRING {
 digitalSignature        (0),
 nonRepudiation          (1),
 keyEncipherment         (2),
 dataEncipherment        (3),
 keyAgreement            (4),
 keyCertSign             (5),
 cRLSign                 (6),
 encipherOnly            (7),
 decipherOnly            (8) }
 */
public class CertToolsImpl implements CertTools {
    private X509Certificate[] certificates;
    private HttpsURLConnection connection;

    private static final  char[] hexDigits = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    private static final  char[] hexDigitsSerial = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    @Override
    public boolean loadServerCerts(String host, Integer port) {
        if (port == null) {
            port = 443;
        }
        try {
            URL url = new URL("https", host, port, "/");
            connection = (HttpsURLConnection)url.openConnection();
            connection.connect();
            certificates = (X509Certificate[]) connection.getServerCertificates();

        } catch (MalformedURLException e) {
            e.printStackTrace();
            return false;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return true;
    }

    @Override
    public void setCerts(Set<X509Certificate> certs) {
        certificates = certs.toArray(new X509Certificate[certs.size()]);
    }

    @Override
    public int getNumberCerts() {
        return certificates.length;
    }

    @Override
    public String getCertRepresentation(int cert) {

        try {
            return  Base64.getEncoder().encodeToString(certificates[cert].getEncoded());
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        }
        return  null;
    }

    @Override
    public String getPublicKey(int cert) {
        return Base64.getEncoder().encodeToString(certificates[cert].getPublicKey().getEncoded());
    }

    @Override
    public String getSignatureAlgorithmName(int cert) {
        return certificates[0].getSigAlgName();
    }

    @Override
    public String getSubjectDistinguishedName(int cert) {
        return certificates[cert].getSubjectDN().getName();
    }

    @Override
    public String getIssuerDistinguishedName(int cert) {
        return certificates[cert].getIssuerDN().getName();
    }

    @Override
    public Date getValidFrom(int cert) {
        return certificates[cert].getNotBefore();
    }

    @Override
    public Date getValidUntil(int cert) {
        return certificates[cert].getNotAfter();
    }

    @Override
    public String getSerialNumber(int cert) {

        byte[] serialnumber = certificates[cert].getSerialNumber().toByteArray();

        StringBuffer stringBuffer = new StringBuffer(serialnumber.length * 2);

        for (byte aDigest : serialnumber) {
            stringBuffer.append(hexDigitsSerial[(aDigest & 0xf0) >> 4]);
            stringBuffer.append(hexDigitsSerial[aDigest & 0x0f]);
        }

        return stringBuffer.toString();
    }

    @Override
    public String getIssuerSerialNumber(int cert) {

        if(cert < certificates.length-2) {
            //non root ca
            return getSerialNumber(cert+1);
        } if (cert == certificates.length-1) {
            //root ca -> self certificated
            return getSerialNumber(cert);
        } else {
            return null;
        }

    }

    @Override
    public String getSignature(int cert) {
        return Base64.getEncoder().encodeToString(certificates[cert].getSignature());
    }

    @Override
    public String getSHA1Fingerprint(int cert) {
       return getFingerprint(cert, "SHA-1");
   }

    private String getFingerprint(int cert, String s) {
        MessageDigest messageDigest = null;
        try {
            messageDigest = MessageDigest.getInstance(s);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        byte[] encoded = new byte[0];
        try {
            encoded = certificates[cert].getEncoded();
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        }

        messageDigest.update(encoded);
        byte[] digest = messageDigest.digest();
        StringBuffer stringBuffer = new StringBuffer(digest.length * 2);

        for (byte aDigest : digest) {
            stringBuffer.append(hexDigits[(aDigest & 0xf0) >> 4]);
            stringBuffer.append(hexDigits[aDigest & 0x0f]);
        }

        return stringBuffer.toString();
    }

    @Override
    public String getSHA256Fingerprint(int cert) {
        return getFingerprint(cert, "SHA-256");      }

    @Override
    public boolean isForDigitalSignature(int cert) {
        return certificates[cert].getKeyUsage()[0];
    }

    @Override
    public boolean isForKeyEncipherment(int cert) {
        return certificates[cert].getKeyUsage()[2];
    }

    @Override
    public boolean isForKeyCertSign(int cert) {
        return certificates[cert].getKeyUsage()[5];
    }

    @Override
    public boolean isForCRLSign(int cert) {
        return certificates[cert].getKeyUsage()[6];
    }

    @Override
    public boolean verifyAllCerts() {
        for (X509Certificate certificate : certificates) {
            try {

                certificate.checkValidity();

            } catch (CertificateExpiredException e) {
                e.printStackTrace();
                return false;
            } catch (CertificateNotYetValidException e) {
                e.printStackTrace();
                return false;
            }
        }

       for(int i = 0 ; i < certificates.length-1 ; i++ ) {
                try {

                    certificates[i].verify(certificates[i+1].getPublicKey());

                } catch (CertificateException e) {
                    e.printStackTrace();
                    return false;
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                    return false;
                } catch (InvalidKeyException e) {
                    e.printStackTrace();
                    return false;
                } catch (NoSuchProviderException e) {
                    e.printStackTrace();
                    return false;
                } catch (SignatureException e) {
                    e.printStackTrace();
                    return false;
                }
            }
        return true;

    }

    @Override
    public int getIsserCertNumber(int cert) {
        boolean[] issuerUniqueID = certificates[cert].getIssuerUniqueID();
        String serialNumber = "";
        if (issuerUniqueID != null) {
            for (Boolean b : issuerUniqueID) {
                if (b) {
                    return 1;
                } else {
                    return 0;
                }
            }
        }
        return -1;
    }

    @Override
    public List<Integer> getCertificateChain() {
        List<Integer> chain = new ArrayList<Integer>();
        Integer i = 0;
        for (Certificate c : certificates) {
            chain.add(i);
            i++;
        }
        return chain;
    }
}
