package net.ripe.commons.provisioning.message;

import com.thoughtworks.xstream.XStream;
import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObjectBuilderException;

import java.io.*;

public class ProvisioningPayloadXmlSerializer extends XStreamXmlSerializer<ProvisioningPayload> {

    public ProvisioningPayloadXmlSerializer(XStream xStream, Class<ProvisioningPayload> objectType) {
        super(xStream, objectType);
    }

    @Override
    public String serialize(ProvisioningPayload object) {
        try {
            return serializeUTF8Encoded(object);
        } catch (IOException e) {
            throw new ProvisioningCmsObjectBuilderException(e);
        }
    }

    private String serializeUTF8Encoded(ProvisioningPayload payload) throws IOException {
        ByteArrayOutputStream outputStream = null;
        Writer writer = null;

        try {
            outputStream = new ByteArrayOutputStream(256);

            writer = new OutputStreamWriter(outputStream, "UTF-8");
            writer.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");

            super.serialize(payload, writer);

            String xml = outputStream.toString("UTF-8");

            return xml.replace("<message", "<message xmlns=\"http://www.apnic.net/specs/rescerts/up-down/\"");
        } finally {
            close(writer);
            close(outputStream);
        }
    }

    private void close(Closeable closeable) {
        if (closeable != null)
        {
            try {
                closeable.close();
            } catch (IOException e) {
                // NOPMD safely ignore
            }
        }
    }
}
