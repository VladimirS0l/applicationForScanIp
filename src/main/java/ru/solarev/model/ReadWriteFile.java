package ru.solarev.model;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.*;

/**
 * Чтение, запись результатов сканирования в файл
 */
public class ReadWriteFile {
    File file = new File("dbScanDomainName.txt");
    Logger log = LoggerFactory.getLogger(ReadWriteFile.class);

    public void writeInFile(String str) {
        try(BufferedWriter bw = new BufferedWriter(new FileWriter(file, true))) {
            bw.write(str);
        } catch (IOException e) {
            log.error(e.getMessage());
        }
    }

    public String readInFile() {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            String temp = br.readLine();
            while (temp != null) {
                sb.append(temp).append("\n");
                temp = br.readLine();
            }
        }catch (IOException ex) {
            ex.printStackTrace();
        }
        return sb.toString();
    }
}
