package ru.solarev.controllers;

import io.javalin.http.Handler;
import ru.solarev.model.SSLCertificateScanner;

/**
 * Класс контроллер содержит в себе обработчики запросов
 */
public class AppController {
    SSLCertificateScanner certificateScanner = new SSLCertificateScanner();

    public Handler showMain = ctx -> {
        ctx.render("/templates/views/main.html");
    };

    public Handler runScan = ctx -> {
        String ip = ctx.formParam("inputIp");
        Integer countThread = Integer.parseInt(ctx.formParam("inputCountThread"));

        certificateScanner.startScanIp(ip, countThread);

        ctx.redirect("/main");
    };
}
