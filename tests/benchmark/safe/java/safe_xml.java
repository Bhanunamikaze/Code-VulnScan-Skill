// BENCHMARK: safe - xxe_mitigated
import javax.servlet.http.*;
import javax.xml.parsers.*;
import org.w3c.dom.*;

public class SafeXmlServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // Safe: explicitly disallow DOCTYPE declarations to prevent XXE
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(request.getInputStream());
        String value = doc.getElementsByTagName("data").item(0).getTextContent();
        response.getWriter().println(value);
    }
}
