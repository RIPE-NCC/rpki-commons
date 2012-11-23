/**
 * The BSD License
 *
 * Copyright (c) 2010-2012 RIPE NCC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   - Neither the name of the RIPE NCC nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
package net.ripe.rpki.xml;

import javax.security.auth.x500.X500Principal;

import net.ripe.rpki.xml.converters.DateTimeConverter;
import net.ripe.rpki.xml.converters.IpResourceConverter;
import net.ripe.rpki.xml.converters.IpResourceSetConverter;
import net.ripe.rpki.xml.converters.JavaUtilTimestampConverter;
import net.ripe.rpki.xml.converters.ManifestCmsConverter;
import net.ripe.rpki.xml.converters.ReadablePeriodConverter;
import net.ripe.rpki.xml.converters.RoaCmsConverter;
import net.ripe.rpki.xml.converters.VersionedIdConverter;
import net.ripe.rpki.xml.converters.X500PrincipalConverter;
import net.ripe.rpki.xml.converters.X509ResourceCertificateConverter;
import net.ripe.rpki.commons.crypto.CertificateRepositoryObject;
import net.ripe.rpki.commons.util.VersionedId;
import net.ripe.ipresource.IpResource;
import net.ripe.ipresource.IpResourceSet;

import org.joda.time.DateTime;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.SingleValueConverter;
import com.thoughtworks.xstream.converters.reflection.Sun14ReflectionProvider;
import com.thoughtworks.xstream.io.HierarchicalStreamDriver;
import com.thoughtworks.xstream.io.xml.XppDriver;
import com.thoughtworks.xstream.mapper.MapperWrapper;

public class XStreamXmlSerializerBuilder<T> {

    private XStream xStream;

    private Class<T> objectType;


    public XStreamXmlSerializerBuilder(Class<T> objectType) {
        this.objectType = objectType;
        createDefaultXStream();  // NOPMD
    }

    private void createDefaultXStream() {
        xStream = new MyXStream(getStreamDriver());
        xStream.setMode(XStream.NO_REFERENCES);
        xStream.aliasPackage("commons", CertificateRepositoryObject.class.getPackage().getName());

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
        withAliasType("versionedId", VersionedId.class);
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

    public final XStreamXmlSerializerBuilder<T> withAliasField(String alias, Class<?> aliasOnField, String field) {
        xStream.useAttributeFor(alias, aliasOnField);
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
            super(new Sun14ReflectionProvider(), hierarchicalStreamDriver);
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
