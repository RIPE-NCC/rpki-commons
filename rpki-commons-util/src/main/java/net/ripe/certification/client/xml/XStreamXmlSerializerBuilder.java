package net.ripe.certification.client.xml;

import javax.security.auth.x500.X500Principal;

import net.ripe.certification.client.xml.converters.DateTimeConverter;
import net.ripe.certification.client.xml.converters.IpResourceConverter;
import net.ripe.certification.client.xml.converters.IpResourceSetConverter;
import net.ripe.certification.client.xml.converters.JavaUtilTimestampConverter;
import net.ripe.certification.client.xml.converters.ManifestCmsConverter;
import net.ripe.certification.client.xml.converters.ReadablePeriodConverter;
import net.ripe.certification.client.xml.converters.RoaCmsConverter;
import net.ripe.certification.client.xml.converters.VersionedIdConverter;
import net.ripe.certification.client.xml.converters.X500PrincipalConverter;
import net.ripe.certification.client.xml.converters.X509ResourceCertificateConverter;
import net.ripe.commons.certification.ValidityPeriod;
import net.ripe.ipresource.IpResource;
import net.ripe.ipresource.IpResourceSet;

import org.joda.time.DateTime;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.SingleValueConverter;
import com.thoughtworks.xstream.io.HierarchicalStreamDriver;
import com.thoughtworks.xstream.io.xml.XppDriver;
import com.thoughtworks.xstream.mapper.MapperWrapper;

public class XStreamXmlSerializerBuilder<T> {

    private XStream xStream;

    private Class<T> objectType;


    public XStreamXmlSerializerBuilder(Class<T> objectType) {
        this.objectType = objectType;
        createDefaultXStream();
    }

    private void createDefaultXStream() {
        xStream = new MyXStream(getStreamDriver());
        xStream.setMode(XStream.NO_REFERENCES);
        xStream.aliasPackage("commons", ValidityPeriod.class.getPackage().getName());

        registerIpResourceRelated();
        registerDateTimeRelated();
        registerRpkiRelated();
    }

    protected HierarchicalStreamDriver getStreamDriver() {
        return new XppDriver();
    }

    protected final Class<T> getObjectType() {
        return objectType;
    }

    private void registerIpResourceRelated() {
        withAliasType("resource", IpResource.class);
        withConverter(new IpResourceConverter());
        withAliasType("resource-set", IpResourceSet.class);
        withConverter(new IpResourceSetConverter());
    }

    private void registerDateTimeRelated() {
        withAliasType("datetime", DateTime.class);
        withConverter(new DateTimeConverter());
        withConverter(new ReadablePeriodConverter());
        withConverter(new JavaUtilTimestampConverter());
    }

    private void registerRpkiRelated() {
        withAliasType("principal", X500Principal.class);
        withConverter(new X500PrincipalConverter());
        withConverter(new VersionedIdConverter());
        withConverter(new X509ResourceCertificateConverter());
        withConverter(new ManifestCmsConverter());
        withConverter(new RoaCmsConverter());
    }

    public final XStreamXmlSerializerBuilder<T> withConverter(Converter converter) {
        xStream.registerConverter(converter);
        return this;
    }

    public final XStreamXmlSerializerBuilder<T> withConverter(SingleValueConverter converter) {
        xStream.registerConverter(converter);
        return this;
    }

    public final XStreamXmlSerializerBuilder<T> withAliasType(String alias, Class<?> type) {
        xStream.aliasType(alias, type);
        return this;
    }

    public final XStreamXmlSerializerBuilder<T> withAliasPackage(String alias, String packageName) {
        xStream.aliasPackage(alias, packageName);
        return this;
    }

    public final XStreamXmlSerializerBuilder<T> withAttribute(String childNode, Class<?> attributeOnType) {
        xStream.useAttributeFor(attributeOnType, childNode);
        return this;
    }

    public final XStreamXmlSerializerBuilder<T> withAliasField(String field, String alias, Class<?> aliasOnField) {
        xStream.aliasField(alias, aliasOnField, field);
        return this;
    }

    public XStreamXmlSerializer<T> build() {
        return new XStreamXmlSerializer<T>(xStream, objectType);
    }

    protected XStream getXStream() {
        return xStream;
    }

    private final class MyXStream extends XStream {

        private MyXStream(HierarchicalStreamDriver hierarchicalStreamDriver) {
            super(hierarchicalStreamDriver);
        }

        /*
        * This code ensures additional fields in the XML get ignored. Useful to maintain backwards compatibility with older version
        * of command objects.
        */
        @Override
        protected MapperWrapper wrapMapper(MapperWrapper next) {
            return new MapperWrapper(next) {
                @Override
                @SuppressWarnings("rawtypes")
                public boolean shouldSerializeMember(Class definedIn, String fieldName) {
                    return definedIn != Object.class && super.shouldSerializeMember(definedIn, fieldName);
                }
            };
        }
    }
}
