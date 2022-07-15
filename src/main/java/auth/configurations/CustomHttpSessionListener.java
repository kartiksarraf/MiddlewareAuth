package auth.configurations;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;

@Configuration
public class CustomHttpSessionListener implements HttpSessionListener {

    @Value("${server.servlet.session.timeout}")
    private Integer sessionTimeout;

    @Override
    public void sessionCreated(HttpSessionEvent event) {
        event.getSession().setMaxInactiveInterval(sessionTimeout);
    }
}