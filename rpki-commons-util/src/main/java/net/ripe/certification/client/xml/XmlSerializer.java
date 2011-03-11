package net.ripe.certification.client.xml;

public interface XmlSerializer<T> {

    String serialize(T object);

    T deserialize(String xml);

}
