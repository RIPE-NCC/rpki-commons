package net.ripe.commons.provisioning.message;

import com.thoughtworks.xstream.io.HierarchicalStreamDriver;
import com.thoughtworks.xstream.io.xml.XmlFriendlyReplacer;
import com.thoughtworks.xstream.io.xml.XppDriver;
import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.certification.client.xml.XStreamXmlSerializerBuilder;

public class ProvisioningPayloadXmlSerializerBuilder<T extends AbstractProvisioningPayload> extends XStreamXmlSerializerBuilder<T> {

    public ProvisioningPayloadXmlSerializerBuilder(Class<T> objectType) {
        super(objectType);
    }

    public XStreamXmlSerializer<T> build() {
        getXStream().processAnnotations(getObjectType());

        return new ProvisioningPayloadXmlSerializer<T>(getXStream(), getObjectType());
    }

    @Override
    protected HierarchicalStreamDriver getStreamDriver() {
        // replace $ with __ and don't replace _
        return new XppDriver(new XmlFriendlyReplacer("__", "_"));
    }
}
