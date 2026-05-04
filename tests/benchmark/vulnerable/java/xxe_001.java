// BENCHMARK: vulnerable - xxe
import javax.servlet.http.*;
import javax.xml.parsers.*;
import org.w3c.dom.*;
import java.io.*;

public class XmlServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // Missing: factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(request.getInputStream());
        String value = doc.getElementsByTagName("data").item(0).getTextContent();
        response.getWriter().println(value);
    }
}
