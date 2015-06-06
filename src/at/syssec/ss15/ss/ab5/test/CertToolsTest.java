package at.syssec.ss15.ss.ab5.test;

import at.syssec.ss15.ss.ab5.CertTools;
import at.syssec.ss15.ss.ab5.impl.kohlbacher_wutti.CertToolsImpl;
import org.junit.Assert;
import org.junit.Test;

import java.util.Arrays;

/**
 * Created by Michael on 06.06.2015.
 */
public class CertToolsTest {

    private CertTools tools = new CertToolsImpl();

    @Test
    public void testCampusAAUZerts() {
        tools.loadServerCerts("campus.aau.at", 443);

        //Hole Zertifikat für campus.aau.at
        int testCert = tools.getCertificateChain().get(0);

        Assert.assertEquals(4, tools.getNumberCerts());

        //Die Reihenfolge kann je nach Implementierung variieren
        Assert.assertEquals(Arrays.asList(0, 1, 2, 3), tools.getCertificateChain());


        Assert.assertEquals(
                "MIIFfTCCBGWgAwIBAgIQN2RgDMIhmaz3l+eMqSZfZjANBgkqhkiG9w0BAQUFADA2MQswCQYDVQQGEwJOTDEPMA0GA1UEChMGVEVSRU5BMRYwFAYDVQQDEw1URVJFTkEgU1NMIENBMB4XDTE0MDQxMDAwMDAwMFoXDTE3MDQwOTIzNTk1OVowOzEhMB8GA1UECxMYRG9tYWluIENvbnRyb2wgVmFsaWRhdGVkMRYwFAYDVQQDEw1jYW1wdXMuYWF1LmF0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5uIWYv3m3+R+aMYImaz3jwrzqlSPfmpxtA7ix8XkCwFK/g4Z/GLZvgmFjKSyvYLZV2Uvyymgxg9iLqj+jqjJsYH4XisT6EuJGi9p+EW0A+8vrthrgRgya9x5UK2DQO3GKRzKe92OS+zknz9xb2ZrL3ykOifCcVfs1cXmdTx0pJLZMFe8aksjiZuIxmcy41MHxKmpWLRd6fCe/SxMxkbdUxOhga5Bbe03ebw88oQRFvu+RGX8CBsGc4fTeJzxAOyj+OLaBYnon0Aigcx4Ma5RzTDYQ9QZmAG8QHO+HptGLjavzlachNDM2Xd82yHorB59NuZOP2Otll2WoafQ2VpTXN7EY2nz41g6Z/jOd0ff6tvCj+4/h3CyWbWIC31TQY0op/Q9J2+7PdZ1Sj3iEYah0KLjNfWMzOp2FpVqrtS9VlMv7qX2LCWakj3+9mZFKT0npRtjOvL8+jDP0MXCIShpO0IsmgLeU6K/kXMsOYeuxgP+Mu2qu+xxfJGJ7CRVJyeTgeSMqSHhx+UoAofZMwKf8bBh53EBsp0ZtvjMeb+t3/p9+PygTPKiHxs5t/NHufoc+Lgydg/wc/M2Z2Ml2PlHJTfGuXCLwdMP2fFUynnCDNFbzQLbhJKyOfe78bhaPJ2OwY3yiW/mmZ+JdghxLF4UoslMuoLNc5T8e862H5RO8CECAwEAAaOCAYAwggF8MB8GA1UdIwQYMBaAFAy9k2gM896ro0lrKzdXR+qQ47ntMB0GA1UdDgQWBBRU0A9MISz9cLlxMfji4VV/bK4rADAOBgNVHQ8BAf8EBAMCBaAwDAYDVR0TAQH/BAIwADAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwIgYDVR0gBBswGTANBgsrBgEEAbIxAQICHTAIBgZngQwBAgEwOgYDVR0fBDMwMTAvoC2gK4YpaHR0cDovL2NybC50Y3MudGVyZW5hLm9yZy9URVJFTkFTU0xDQS5jcmwwbQYIKwYBBQUHAQEEYTBfMDUGCCsGAQUFBzAChilodHRwOi8vY3J0LnRjcy50ZXJlbmEub3JnL1RFUkVOQVNTTENBLmNydDAmBggrBgEFBQcwAYYaaHR0cDovL29jc3AudGNzLnRlcmVuYS5vcmcwLgYDVR0RBCcwJYINY2FtcHVzLmFhdS5hdIIUY2FtcHVzLnVuaS1rbHUuYWMuYXQwDQYJKoZIhvcNAQEFBQADggEBACGhdXOKGIhoiDxtMtgRzfeZhJJJCY81rVwmj/VyNlZ3YNcJHnBXxB8pZdm3drJ1pKt01Too73gydHAYWnPwZdT/HNtEKFFPP5HFVx4POFm9OIMu2OL3MQICvxaRWB/YcurJWP0ijG6WGxMe9ieq3QmtTYuLbF8UaHaED5wt4yzBTFooMXma6/xu3geFz7FlgU0IyuLfsEI3j5OBv9JcFhlxbMPk2UecFsW+DI/8w2WFOx0yNRGotYkUTG7Zu79jYykBB7nEu16QQmS/Ped/U1ruLHRZFOKU2ztUnwJgSgH193oFHRTkcMxJjEgA7u3NhQDV6Lk2VPMlQdOuyYqAaQU=",
                tools.getCertRepresentation(testCert));

        Assert.assertEquals(
                "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5uIWYv3m3+R+aMYImaz3jwrzqlSPfmpxtA7ix8XkCwFK/g4Z/GLZvgmFjKSyvYLZV2Uvyymgxg9iLqj+jqjJsYH4XisT6EuJGi9p+EW0A+8vrthrgRgya9x5UK2DQO3GKRzKe92OS+zknz9xb2ZrL3ykOifCcVfs1cXmdTx0pJLZMFe8aksjiZuIxmcy41MHxKmpWLRd6fCe/SxMxkbdUxOhga5Bbe03ebw88oQRFvu+RGX8CBsGc4fTeJzxAOyj+OLaBYnon0Aigcx4Ma5RzTDYQ9QZmAG8QHO+HptGLjavzlachNDM2Xd82yHorB59NuZOP2Otll2WoafQ2VpTXN7EY2nz41g6Z/jOd0ff6tvCj+4/h3CyWbWIC31TQY0op/Q9J2+7PdZ1Sj3iEYah0KLjNfWMzOp2FpVqrtS9VlMv7qX2LCWakj3+9mZFKT0npRtjOvL8+jDP0MXCIShpO0IsmgLeU6K/kXMsOYeuxgP+Mu2qu+xxfJGJ7CRVJyeTgeSMqSHhx+UoAofZMwKf8bBh53EBsp0ZtvjMeb+t3/p9+PygTPKiHxs5t/NHufoc+Lgydg/wc/M2Z2Ml2PlHJTfGuXCLwdMP2fFUynnCDNFbzQLbhJKyOfe78bhaPJ2OwY3yiW/mmZ+JdghxLF4UoslMuoLNc5T8e862H5RO8CECAwEAAQ==",
                tools.getPublicKey(testCert));

        Assert.assertEquals(
                "IaF1c4oYiGiIPG0y2BHN95mEkkkJjzWtXCaP9XI2Vndg1wkecFfEHyll2bd2snWkq3TVOijveDJ0cBhac/Bl1P8c20QoUU8/kcVXHg84Wb04gy7Y4vcxAgK/FpFYH9hy6slY/SKMbpYbEx72J6rdCa1Ni4tsXxRodoQPnC3jLMFMWigxeZrr/G7eB4XPsWWBTQjK4t+wQjePk4G/0lwWGXFsw+TZR5wWxb4Mj/zDZYU7HTI1Eai1iRRMbtm7v2NjKQEHucS7XpBCZL89539TWu4sdFkU4pTbO1SfAmBKAfX3egUdFORwzEmMSADu7c2FANXouTZU8yVB067JioBpBQ==",
                tools.getSignature(testCert));

        Assert.assertEquals(false, tools.isForCRLSign(testCert));
        Assert.assertEquals(true, tools.isForDigitalSignature(testCert));
        Assert.assertEquals(false, tools.isForKeyCertSign(testCert));
        Assert.assertEquals(true, tools.isForKeyEncipherment(testCert));

        Assert.assertEquals("3764600cc22199acf797e78ca9265f66", tools.getSerialNumber(testCert));

        Assert.assertEquals("4bc814032f07fa6aa4f0da29df6179ba", tools.getIssuerSerialNumber(testCert));

        Assert.assertEquals("867F46C109CA8FF4015D9AE0EC80933AAA37DACC", tools.getSHA1Fingerprint(testCert));
        Assert.assertEquals("43674EF8882F1D5A06A7A8E83DD5A967AB9F4AEB929212D956BC49E9D6EF45B4", tools.getSHA256Fingerprint(testCert));

        Assert.assertEquals("SHA1withRSA", tools.getSignatureAlgorithmName(testCert));

        Assert.assertEquals("CN=campus.aau.at, OU=Domain Control Validated", tools.getSubjectDistinguishedName(testCert));
        Assert.assertEquals("CN=TERENA SSL CA, O=TERENA, C=NL", tools.getIssuerDistinguishedName(testCert));

        Assert.assertEquals(true, tools.verifyAllCerts());


        int rootCA = tools.getCertificateChain().get(3);
        //Die RootCA hat sich selbst zertifiziert
        Assert.assertEquals(tools.getSerialNumber(rootCA), tools.getIssuerSerialNumber(rootCA));
        Assert.assertEquals(tools.getSubjectDistinguishedName(rootCA), tools.getIssuerDistinguishedName(rootCA));
    }
}
