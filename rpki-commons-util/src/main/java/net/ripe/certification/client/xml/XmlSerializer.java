package net.ripe.certification.client.xml;

import java.io.Writer;

public interface XmlSerializer<T> {

    String serialize(T object);
    void serialize(T object, Writer writer);

    T deserialize(String xml);

}
