package ru.solarev.model;

import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressString;
import org.apache.http.HttpResponseInterceptor;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ManagedHttpClientConnection;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpCoreContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.net.ssl.SSLSession;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Класс для парсинга Ip и поиска доменных имен
 */
public class SSLCertificateScanner {
    Logger log = LoggerFactory.getLogger(SSLCertificateScanner.class);
    public static final String PEER_CERTIFICATES = "PEER_CERTIFICATES";
    ReadWriteFile rwf = new ReadWriteFile();

    public void startScanIp(String ip, Integer countThread) {
        int numThreads = countThread;
        ExecutorService executorService = Executors.newFixedThreadPool(numThreads);
        IPAddress allAddress = subnetToIps(ip);

        for (IPAddress addr : allAddress.getAddresses()) {
            Runnable scannerTask = () -> {
                try {
                    String sc = scanIp("https://" + addr);
                    rwf.writeInFile(sc);
                } catch (IOException e) {
                    log.error(e.getMessage());
                }
            };
            executorService.execute(scannerTask);
        }
        executorService.shutdown();
    }

    public String scanIp(String ip) throws IOException {
        StringBuilder sb = new StringBuilder();
        HttpResponseInterceptor certificateInterceptor = (httpResponse, context) -> {
            ManagedHttpClientConnection routedConnection = (ManagedHttpClientConnection) context
                    .getAttribute(HttpCoreContext.HTTP_CONNECTION);
            SSLSession sslSession = routedConnection.getSSLSession();
            if (sslSession != null) {
                Certificate[] certificates = sslSession.getPeerCertificates();
                context.setAttribute(PEER_CERTIFICATES, certificates);
            }
        };

        CloseableHttpClient httpClient = HttpClients
                .custom()
                .addInterceptorLast(certificateInterceptor)
                .build();

        try {
            HttpGet httpget = new HttpGet(ip);
            HttpContext context = new BasicHttpContext();
            httpClient.execute(httpget, context);
            Certificate[] peerCertificates = (Certificate[]) context.getAttribute(PEER_CERTIFICATES);

            sb.append("\n").append(ip).append("---------------------------------------------------------\n");
            for (Certificate certificate : peerCertificates) {
                X509Certificate real = (X509Certificate) certificate;
                sb.append(ip).append(": domain name - ").append(real.getSubjectX500Principal()).append("\n");
            }
        } catch (ClientProtocolException e) {
            log.error(e.getMessage());
        } finally {
            httpClient.close();
        }
        return sb.toString();
    }

    public IPAddress subnetToIps(String ipOrCidr) {
        IPAddressString addrString = new IPAddressString(ipOrCidr, IPAddressString.ALL_ADDRESSES.getValidationOptions());
        return addrString.getAddress();
    }
}

