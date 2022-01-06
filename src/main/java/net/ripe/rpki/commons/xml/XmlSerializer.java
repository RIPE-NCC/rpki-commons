package net.ripe.rpki.commons.xml;

public interface XmlSerializer<T> {

    String serialize(T object);

    T deserialize(String xml);

}
