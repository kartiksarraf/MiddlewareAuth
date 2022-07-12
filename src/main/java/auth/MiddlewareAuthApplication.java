package auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;

@SpringBootApplication()
public class MiddlewareAuthApplication extends SpringBootServletInitializer {

    /**
     * SpringApplicationBuilder: Main purpose is to create WAR file for tomcat deployment
     *
     * @param application
     * @return
     */
    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
        return application.sources(MiddlewareAuthApplication.class);
    }

    public static void main(String[] args) {
        SpringApplication.run(MiddlewareAuthApplication.class, args);
    }

}
