// BENCHMARK: safe - prepared_statement
import javax.servlet.http.*;
import java.sql.*;

public class SafeUserServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        String userId = request.getParameter("id");
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "pass");
        // Safe: PreparedStatement with parameterized query
        PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        stmt.setString(1, userId);
        ResultSet rs = stmt.executeQuery();
        while (rs.next()) {
            response.getWriter().println(rs.getString("username"));
        }
        conn.close();
    }
}
