package ru.solarev;

import io.javalin.Javalin;
import ru.solarev.controllers.AppController;

/**
 * Класс для запуска приложения
 */
class App {

    public static void main( String[] args ) {
        Javalin app = Javalin.create().start(7070);
        addRoutes(app);
    }

    private static void addRoutes(Javalin app) {
        AppController appController = new AppController();
        app.get("/main", appController.showMain);
        app.post("/new", appController.runScan);
    }
}
