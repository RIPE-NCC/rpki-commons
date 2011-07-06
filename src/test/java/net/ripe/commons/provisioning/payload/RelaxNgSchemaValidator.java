package net.ripe.commons.provisioning.payload;


import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;
import java.io.File;
import java.io.IOException;
import java.io.StringReader;

public abstract class RelaxNgSchemaValidator {

    private static final String SCHEMA_LOCATION = "src/test/resources/provisioning.rnc";

    /**
     * Validate against a relax ng schema
     * @param xml to validate
     * @return true when all is valid
     * @throws IOException upon failures
     * @throws SAXException upon failures
     */
    public static boolean validateAgainstRelaxNg(String xml) throws IOException, SAXException {
        System.setProperty(SchemaFactory.class.getName() + ":" + XMLConstants.RELAXNG_NS_URI, "com.thaiopensource.relaxng.jaxp.CompactSyntaxSchemaFactory");

        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.RELAXNG_NS_URI);

        File schemaLocation = new File(SCHEMA_LOCATION);
        Schema schema = factory.newSchema(schemaLocation);

        Validator validator = schema.newValidator();

        StreamSource source = new StreamSource(new StringReader(xml));

        validator.validate(source);

        return true;
    }
}
