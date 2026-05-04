// BENCHMARK: vulnerable - cmdi
import javax.servlet.http.*;
import java.io.*;

public class PingServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        String host = request.getParameter("host");
        Runtime runtime = Runtime.getRuntime();
        Process proc = runtime.exec("ping -c 1 " + host);
        BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()));
        String line;
        while ((line = reader.readLine()) != null) {
            response.getWriter().println(line);
        }
    }
}
