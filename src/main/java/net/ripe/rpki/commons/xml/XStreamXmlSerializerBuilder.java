package net.ripe.rpki.commons.xml;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.SingleValueConverter;
import com.thoughtworks.xstream.converters.reflection.SunUnsafeReflectionProvider;
import com.thoughtworks.xstream.io.HierarchicalStreamDriver;
import com.thoughtworks.xstream.io.xml.XppDriver;
import com.thoughtworks.xstream.mapper.MapperWrapper;
import com.thoughtworks.xstream.security.NoTypePermission;
import com.thoughtworks.xstream.security.NullPermission;
import com.thoughtworks.xstream.security.PrimitiveTypePermission;
import net.ripe.ipresource.IpResource;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms;
import net.ripe.rpki.commons.crypto.cms.roa.RoaCms;
import net.ripe.rpki.commons.crypto.cms.roa.RoaPrefix;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.util.VersionedId;
import net.ripe.rpki.commons.validation.roa.AnnouncedRoute;
import net.ripe.rpki.commons.validation.roa.RouteValidityState;
import net.ripe.rpki.commons.xml.converters.InstantConverter;
import net.ripe.rpki.commons.xml.converters.IpResourceConverter;
import net.ripe.rpki.commons.xml.converters.IpResourceSetConverter;
import net.ripe.rpki.commons.xml.converters.JavaUtilTimestampConverter;
import net.ripe.rpki.commons.xml.converters.ManifestCmsConverter;
import net.ripe.rpki.commons.xml.converters.RoaCmsConverter;
import net.ripe.rpki.commons.xml.converters.VersionedIdConverter;
import net.ripe.rpki.commons.xml.converters.X500PrincipalConverter;
import net.ripe.rpki.commons.xml.converters.X509ResourceCertificateConverter;

import javax.security.auth.x500.X500Principal;
import java.time.Instant;

public class XStreamXmlSerializerBuilder<T> {

    private static final boolean STRICT = true;
    private static final boolean NOT_STRICT = false;
    private XStream xStream;

    private final Class<T> objectType;


    public static <C> XStreamXmlSerializerBuilder<C> newStrictXmlSerializerBuilder(Class<C> objectType) {
        return new XStreamXmlSerializerBuilder<>(objectType, STRICT);
    }

    public static <C> XStreamXmlSerializerBuilder<C> newForgivingXmlSerializerBuilder(Class<C> objectType) {
        return new XStreamXmlSerializerBuilder<>(objectType, NOT_STRICT);
    }

    protected XStreamXmlSerializerBuilder(Class<T> objectType, boolean strict) {
        this.objectType = objectType;
        createDefaultXStream(strict);
    }

    /**
     * Instantiate XStream and set-up the security framework to prevent injection and remote code execution.
     *
     * Types that are allowed are:
     *   * A list of default types included in XStream.
     *   * The type the serializer is built for.
     *   * Types that have been aliased (i.e. the mapped name of the class is not it's qualified name).
     *
     * Note that the whitelist is <emph>only</emph> checked on deserialization.
     */
    private void createDefaultXStream(boolean strict) {
        if(strict) {
            xStream = new XStream();
        } else {
            xStream = new MyXStream(getStreamDriver());
        }

        xStream.setMode(XStream.NO_REFERENCES);

        // Prohibit deserialisation of all types
        xStream.addPermission(NoTypePermission.NONE);

        // And only add the necessary ones
        xStream.addPermission(NullPermission.NULL);
        xStream.addPermission(PrimitiveTypePermission.PRIMITIVES);

        // Allow type this serializer is instantiated for as well as its descendant types
        xStream.allowTypeHierarchy(this.objectType);
        xStream.allowTypes(new Class[]{ this.objectType });
        // Not all registered types are part of this module.
        // A wildcard could pull in classes that are not safe to deserialize -> allow types from net.ripe
        // for which there exists an alias.
        xStream.addPermission(new AliasedNetRipeTypePermission(xStream));

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
        // Explictly allow Period without aliasing.
        withAliasClass("datetime", Instant.class);
        withConverter(new InstantConverter());
        withConverter(new JavaUtilTimestampConverter());
        withAliasClass("ValidityPeriod", ValidityPeriod.class);
    }

    private void registerRpkiRelated() {
        withAliasClass("X509ResourceCertificate", X509ResourceCertificate.class);
        withAliasClass("X509Crl", X509Crl.class);
        withAliasClass("ManifestCms", ManifestCms.class);
        withAliasClass("RoaCms", RoaCms.class);
        withAliasClass("RouteValidityState", RouteValidityState.class);
        withAliasClass("RoaPrefix", RoaPrefix.class);
        withAliasClass("AnnouncedRoute", AnnouncedRoute.class);
        withAliasClass("X509CertificateInformationAccessDescriptor", X509CertificateInformationAccessDescriptor.class);

        withAliasClass("principal", X500Principal.class);
        withConverter(new X500PrincipalConverter());
        withAliasClass("versionedId", VersionedId.class);
        withConverter(new VersionedIdConverter());

        withConverter(new X509ResourceCertificateConverter());
        withAllowedType(X509ResourceCertificate.class);

        withConverter(new ManifestCmsConverter());
        withAllowedType(ManifestCms.class);

        withConverter(new RoaCmsConverter());
        withAllowedType(RoaCms.class);
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

    public final XStreamXmlSerializerBuilder<T> withAliasClass(String alias, Class<?> type) {
        xStream.alias(alias, type);
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

    /**
     * Explicitly allow a type to be serialized without using an alias
     * @param classType type to allow.
     */
    public final XStreamXmlSerializerBuilder<T> withAllowedType(Class<?> classType) {
        xStream.allowTypes(new Class[]{classType});
        return this;
    }

    /**
     * Explicitly allow a type and it's descendant types to be serialized without using an alias
     * @param classType parent type to allow.
     */
    public final XStreamXmlSerializerBuilder<T> withAllowedTypeHierarchy(Class<?> classType) {
        xStream.allowTypeHierarchy(classType);
        return this;
    }

    public final XStreamXmlSerializerBuilder<T> withAliasField(String alias, Class<?> aliasOnField, String field) {
        xStream.useAttributeFor(alias, aliasOnField);
        // transitive: aliasField allows serialization for field type.
        xStream.aliasField(alias, aliasOnField, field);
        return this;
    }

    public XStreamXmlSerializer<T> build() {
        return new XStreamXmlSerializer<>(xStream, objectType);
    }

    protected XStream getXStream() {
        return xStream;
    }

    private static final class MyXStream extends XStream {

        private MyXStream(HierarchicalStreamDriver hierarchicalStreamDriver) {
            super(new SunUnsafeReflectionProvider(), hierarchicalStreamDriver);
        }

        /*
        * This code ensures additional fields in the XML get ignored. Useful to maintain backwards compatibility with older version
        * of command objects.
        */
        @Override
        protected MapperWrapper wrapMapper(MapperWrapper next) {
            return new MapperWrapper(next) {
                @Override
                public boolean shouldSerializeMember(Class definedIn, String fieldName) {
                    return definedIn != Object.class && super.shouldSerializeMember(definedIn, fieldName);
                }
            };
        }
    }
}
