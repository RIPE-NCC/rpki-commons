package net.ripe.rpki.commons.xml;

import net.ripe.rpki.commons.provisioning.identity.IdentitySerializerException;

public interface XmlSerializer<T> {

    String serialize(T object) throws IdentitySerializerException;

    T deserialize(String xml) throws IdentitySerializerException;

}
