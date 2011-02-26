package net.ripe.certification.client.xml;

import com.thoughtworks.xstream.XStream;

public class XStreamXmlSerializer<T> implements XmlSerializer<T> {

    private final XStream xStream;

    private final Class<T> objectType;


    public XStreamXmlSerializer(XStream xStream, Class<T> objectType) {
        super();
        this.xStream = xStream;
        this.objectType = objectType;
    }

    @Override
    public T deserialize(String xml) {
        return objectType.cast(xStream.fromXML(xml));
    }

    @Override
    public String serialize(T object) {
        return xStream.toXML(object);
    }
}
