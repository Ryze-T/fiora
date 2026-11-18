import javax.xml.parsers.*;
import org.xml.sax.InputSource;
import java.io.StringReader;
public class XmlImport {
    public void parse(String xml) throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        DocumentBuilder b = f.newDocumentBuilder();
        b.parse(new InputSource(new StringReader(xml)));
    }
}
