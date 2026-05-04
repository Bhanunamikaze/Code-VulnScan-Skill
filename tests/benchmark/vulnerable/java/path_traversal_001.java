// BENCHMARK: vulnerable - path_traversal
import javax.servlet.http.*;
import java.io.*;
import java.nio.file.*;

public class FileServlet extends HttpServlet {
    private static final String BASE_DIR = "/var/app/files/";

    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        String path = request.getParameter("path");
        File file = new File(BASE_DIR + path);
        byte[] content = Files.readAllBytes(file.toPath());
        response.getOutputStream().write(content);
    }
}
