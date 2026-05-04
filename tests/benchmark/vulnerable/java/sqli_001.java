// BENCHMARK: vulnerable - sqli
import javax.servlet.http.*;
import java.sql.*;

public class UserServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        String userId = request.getParameter("id");
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "pass");
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id=" + userId);
        while (rs.next()) {
            response.getWriter().println(rs.getString("username"));
        }
        conn.close();
    }
}
